package com.psia.pkoc.core;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import com.upokecenter.cbor.CBORObject;

import org.bouncycastle.util.encoders.Hex;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * AliroAccessDocument — CBOR Access Document builder, parser, and verifier.
 *
 * Implements Aliro 1.0 §7 (Access Document) and §8.4 (Step-Up phase).
 *
 * Supports two modes:
 *   1. Self-generated test document — generates issuer keypair on-device, self-signs a
 *      minimal AccessData element. Good for testing Step-Up flow without a real issuer.
 *   2. Imported document — accepts a Base64-encoded CBOR blob from an external issuer.
 *
 * CBOR structure per Aliro §7.2 (ISO 18013-5 §9.1.2 with Aliro modifications):
 *
 * Access Document (DocType "aliro-a"):
 *   issuerSigned:
 *     nameSpaces ("aliro-a"):
 *       [IssuerSignedItem, ...]
 *     IssuerAuth:  COSE_Sign1 [ header, nil, MobileSecurityObject, signature ]
 *       MobileSecurityObject:
 *         "1": version ("1.0")
 *         "2": digestAlgorithm ("SHA-256")
 *         "3": valueDigests { "aliro-a": { digestID -> SHA-256(IssuerSignedItem) } }
 *         "4": deviceKeyInfo { "1": COSE_Key of credential pub key }
 *         "5": docType ("aliro-a")
 *         "6": validityInfo { "1": signed, "2": validFrom, "3": validUntil }
 *         "7": timeVerificationRequired (boolean, SHALL be present per §7.2.2)
 *
 * Revocation Document (DocType "aliro-r"):
 *   issuerSigned:
 *     nameSpaces ("aliro-r"):
 *       [IssuerSignedItem, ...]
 *     IssuerAuth:  COSE_Sign1 [ header, nil, MobileSecurityObject, signature ]
 *       MobileSecurityObject:
 *         "1": version ("1.0")
 *         "2": digestAlgorithm ("SHA-256")
 *         "3": valueDigests { "aliro-r": { digestID -> SHA-256(IssuerSignedItem) } }
 *         (NO "4" deviceKeyInfo — per Aliro §7.6)
 *         "5": docType ("aliro-r")
 *         "6": validityInfo { "1": signed, "2": validFrom, "3": validUntil }
 *         "7": timeVerificationRequired (boolean)
 *
 * IssuerSignedItem (per Table 7-2):
 *   "1": digestID (uint)
 *   "2": random (bstr, 16 bytes)
 *   "3": elementIdentifier (tstr)
 *   "4": elementValue (AccessData map)
 *
 * AccessData (per §7.3):
 *   0: version (uint = 1)
 *   1: id (bstr, optional)
 *   2: AccessRules array (optional)
 *   3: Schedules array (optional)
 *
 * AccessRule (per §7.3.3):
 *   0: capabilities (uint, bitmask)
 *   1: allowScheduleIds (uint, bitmask of schedule indices)
 *
 * Schedule (per §7.3.4):
 *   0: startPeriod (uint, unix epoch seconds)
 *   1: endPeriod (uint, unix epoch seconds)
 *   2: recurrenceRule array [durationSeconds, mask, pattern, interval, ordinal]
 *   3: flags (uint, bit 0 = Time_in_UTC)
 *
 * Storage: stored as Base64-encoded CBOR in SharedPreferences under key "aliro_access_doc".
 * The issuer public key (for reader-side verification) is stored separately under
 * "aliro_access_doc_issuer_pub_key" as 65-byte uncompressed hex.
 */
public class AliroAccessDocument
{
    private static final String TAG = "AliroAccessDocument";

    // SharedPreferences keys
    public static final String PREFS_NAME         = "AliroCredentialConfig";
    public static final String KEY_ACCESS_DOC     = "aliro_access_doc";           // Base64 CBOR
    public static final String KEY_ISSUER_PUB_KEY = "aliro_access_doc_issuer_pub_key"; // hex
    public static final String KEY_ISSUER_PRIV_KEY = "aliro_access_doc_issuer_priv_key"; // PKCS#8 hex
    public static final String KEY_ELEMENT_ID     = "aliro_access_doc_element_id"; // first element (back-compat)
    public static final String KEY_ELEMENT_IDS    = "aliro_access_doc_element_ids"; // CSV of all elements
    public static final String KEY_DOC_MODE       = "aliro_access_doc_mode";      // "test" or "imported"
    public static final String KEY_DOC_VALID_FROM = "aliro_access_doc_valid_from"; // ISO-8601
    public static final String KEY_DOC_VALID_UNTIL= "aliro_access_doc_valid_until";// ISO-8601

    // Revocation Document SharedPreferences keys
    public static final String KEY_REVOC_DOC            = "aliro_revocation_doc";           // Base64 CBOR
    public static final String KEY_REVOC_ISSUER_PUB_KEY = "aliro_revoc_doc_issuer_pub_key"; // hex
    public static final String KEY_REVOC_ISSUER_PRIV_KEY = "aliro_revoc_doc_issuer_priv_key"; // PKCS#8 hex
    public static final String KEY_REVOC_ELEMENT_ID     = "aliro_revoc_doc_element_id";     // first element (back-compat)
    public static final String KEY_REVOC_ELEMENT_IDS    = "aliro_revoc_doc_element_ids";    // CSV of all elements

    // Aliro doc type and namespace constants
    public static final String DOCTYPE_ACCESS      = "aliro-a";
    public static final String NAMESPACE_ACCESS    = "aliro-a";

    // Aliro Revocation Document constants (per §7.6)
    public static final String DOCTYPE_REVOCATION  = "aliro-r";
    public static final String NAMESPACE_REVOCATION = "aliro-r";

    // -------------------------------------------------------------------------
    // Multi-Document storage (Aliro 1.0 §7.7)
    //
    // The credential may carry multiple Access Documents at once, each with
    // its own issuer keypair and its own kid. This is the normal real-world
    // case — different employers, different facilities, different trust roots.
    //
    // Storage layout:
    //
    //   aliro_doc_ids               — CSV of all stored document slugs
    //                                 (auto-generated, e.g. "doc_1730482931_a4f2")
    //   aliro_current_doc_id        — slug of the "current" / selected document
    //                                 (operations without an explicit docId
    //                                 default to this; UI shows it as selected)
    //
    //   For each docId, the per-document keys are the legacy KEY_* names with
    //   the docId appended after a colon:
    //
    //     aliro_access_doc:<docId>                   — Base64 CBOR
    //     aliro_access_doc_issuer_pub_key:<docId>    — hex
    //     aliro_access_doc_issuer_priv_key:<docId>   — PKCS#8 hex
    //     aliro_access_doc_element_ids:<docId>       — CSV
    //     aliro_access_doc_mode:<docId>              — "test" / "sample" / etc
    //     aliro_access_doc_valid_from:<docId>        — ISO-8601
    //     aliro_access_doc_valid_until:<docId>       — ISO-8601
    //     aliro_access_doc_label:<docId>             — user-friendly name
    //
    //     aliro_revocation_doc:<docId>               — Base64 CBOR
    //     aliro_revoc_doc_issuer_pub_key:<docId>     — hex
    //     aliro_revoc_doc_issuer_priv_key:<docId>    — PKCS#8 hex
    //     aliro_revoc_doc_element_ids:<docId>        — CSV
    //
    // Back-compat / migration: the legacy single-doc keys (without :<docId>)
    // are read once on first multi-doc access, copied into a freshly minted
    // docId entry, and then removed. Old installs upgrade transparently.
    //
    // Default behavior of methods that do not take a docId argument:
    //   reads operate on the current doc; writes create one if none exists.
    // -------------------------------------------------------------------------

    /** Top-level CSV of all stored Access Document IDs. */
    public static final String KEY_DOC_IDS         = "aliro_doc_ids";
    /** ID of the currently selected document (UI-driven). */
    public static final String KEY_CURRENT_DOC_ID  = "aliro_current_doc_id";

    /** Per-document key suffix for the user-friendly label shown in the UI. */
    private static final String SUFFIX_LABEL       = "aliro_access_doc_label";

    /**
     * Build a per-document SharedPreferences key by appending a colon and the
     * docId to a base key name. The colon is illegal in element identifiers
     * so there's no collision with element-named substrings.
     */
    private static String docKey(String baseKey, String docId)
    {
        return baseKey + ":" + docId;
    }

    /**
     * Allocate a fresh document ID. Format is {@code doc_<epochSec>_<rand4>}
     * — sortable by creation time, short enough to display, unique enough
     * for a single device.
     */
    private static String allocateDocId()
    {
        long now = System.currentTimeMillis() / 1000L;
        int rand = new java.security.SecureRandom().nextInt(0xFFFF);
        return String.format("doc_%d_%04x", now, rand);
    }

    /**
     * Run the one-shot migration from legacy single-doc storage to multi-doc
     * storage. Idempotent. Called from every public method that reads the
     * list of documents so old installs upgrade lazily on first access.
     *
     * <p>If the legacy {@code aliro_access_doc} key is present and the
     * doc-ID list is empty, mints a docId, copies the legacy values across,
     * removes the legacy keys, and sets the new docId as current.
     */
    private static void migrateLegacyIfNeeded(Context context)
    {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String docIds = prefs.getString(KEY_DOC_IDS, "");
        if (!docIds.isEmpty()) return;                    // already multi-doc
        String legacyDoc = prefs.getString(KEY_ACCESS_DOC, null);
        if (legacyDoc == null) return;                    // nothing to migrate

        try
        {
            String docId = allocateDocId();
            SharedPreferences.Editor ed = prefs.edit();
            // Copy legacy keys into per-doc namespaced keys.
            ed.putString(docKey(KEY_ACCESS_DOC, docId),       legacyDoc);
            String legacyPub = prefs.getString(KEY_ISSUER_PUB_KEY, "");
            if (!legacyPub.isEmpty())
                ed.putString(docKey(KEY_ISSUER_PUB_KEY, docId), legacyPub);
            String legacyPriv = prefs.getString(KEY_ISSUER_PRIV_KEY, "");
            if (!legacyPriv.isEmpty())
                ed.putString(docKey(KEY_ISSUER_PRIV_KEY, docId), legacyPriv);
            String legacyElems = prefs.getString(KEY_ELEMENT_IDS, "");
            if (legacyElems.isEmpty())
            {
                // older still: only KEY_ELEMENT_ID was set
                String single = prefs.getString(KEY_ELEMENT_ID, "");
                if (!single.isEmpty()) legacyElems = single;
            }
            ed.putString(docKey(KEY_ELEMENT_IDS, docId), legacyElems);
            String legacyMode = prefs.getString(KEY_DOC_MODE, "imported");
            ed.putString(docKey(KEY_DOC_MODE, docId), legacyMode);
            String legacyFrom  = prefs.getString(KEY_DOC_VALID_FROM, "");
            String legacyUntil = prefs.getString(KEY_DOC_VALID_UNTIL, "");
            ed.putString(docKey(KEY_DOC_VALID_FROM,  docId), legacyFrom);
            ed.putString(docKey(KEY_DOC_VALID_UNTIL, docId), legacyUntil);
            // Use the doc-mode label as a default friendly name.
            ed.putString(docKey(SUFFIX_LABEL, docId), "Document 1");

            // Revocation companion (if any).
            String legacyRevocDoc = prefs.getString(KEY_REVOC_DOC, null);
            if (legacyRevocDoc != null)
            {
                ed.putString(docKey(KEY_REVOC_DOC, docId), legacyRevocDoc);
                String revocPub  = prefs.getString(KEY_REVOC_ISSUER_PUB_KEY,  "");
                String revocPriv = prefs.getString(KEY_REVOC_ISSUER_PRIV_KEY, "");
                String revocElems= prefs.getString(KEY_REVOC_ELEMENT_IDS,     "");
                if (!revocPub.isEmpty())   ed.putString(docKey(KEY_REVOC_ISSUER_PUB_KEY,  docId), revocPub);
                if (!revocPriv.isEmpty())  ed.putString(docKey(KEY_REVOC_ISSUER_PRIV_KEY, docId), revocPriv);
                if (!revocElems.isEmpty()) ed.putString(docKey(KEY_REVOC_ELEMENT_IDS,     docId), revocElems);
            }

            // List + current pointer.
            ed.putString(KEY_DOC_IDS, docId);
            ed.putString(KEY_CURRENT_DOC_ID, docId);

            // Remove legacy keys so we don't double-migrate.
            ed.remove(KEY_ACCESS_DOC).remove(KEY_ISSUER_PUB_KEY).remove(KEY_ISSUER_PRIV_KEY)
              .remove(KEY_ELEMENT_ID).remove(KEY_ELEMENT_IDS).remove(KEY_DOC_MODE)
              .remove(KEY_DOC_VALID_FROM).remove(KEY_DOC_VALID_UNTIL);
            ed.remove(KEY_REVOC_DOC).remove(KEY_REVOC_ISSUER_PUB_KEY)
              .remove(KEY_REVOC_ISSUER_PRIV_KEY).remove(KEY_REVOC_ELEMENT_ID)
              .remove(KEY_REVOC_ELEMENT_IDS);
            ed.apply();
            Log.i(TAG, "migrateLegacyIfNeeded: migrated legacy single-doc storage to docId=" + docId);
        }
        catch (Exception e)
        {
            Log.w(TAG, "migrateLegacyIfNeeded failed", e);
        }
    }

    /** Return the ordered list of stored document IDs (most recently created last). */
    public static List<String> getDocumentIds(Context context)
    {
        migrateLegacyIfNeeded(context);
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String csv = prefs.getString(KEY_DOC_IDS, "");
        List<String> out = new ArrayList<>();
        if (!csv.isEmpty())
        {
            for (String s : csv.split(","))
            {
                String t = s.trim();
                if (!t.isEmpty()) out.add(t);
            }
        }
        return out;
    }

    /**
     * Return the currently-selected document ID. Falls back to the first ID
     * in the list if no current is set, or null if no documents exist.
     */
    public static String getCurrentDocumentId(Context context)
    {
        migrateLegacyIfNeeded(context);
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String current = prefs.getString(KEY_CURRENT_DOC_ID, "");
        List<String> ids = getDocumentIds(context);
        if (!current.isEmpty() && ids.contains(current)) return current;
        return ids.isEmpty() ? null : ids.get(0);
    }

    /** Set the currently-selected document. No-op if {@code docId} is unknown. */
    public static void setCurrentDocumentId(Context context, String docId)
    {
        if (docId == null) return;
        if (!getDocumentIds(context).contains(docId)) return;
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putString(KEY_CURRENT_DOC_ID, docId).apply();
    }

    /**
     * Return the user-friendly label for a stored document, or a default of
     * {@code "Document N"} where N is the 1-based position in the list.
     */
    public static String getDocumentLabel(Context context, String docId)
    {
        if (docId == null) return "";
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String label = prefs.getString(docKey(SUFFIX_LABEL, docId), "");
        if (!label.isEmpty()) return label;
        int idx = getDocumentIds(context).indexOf(docId);
        return "Document " + (idx >= 0 ? (idx + 1) : "?");
    }

    /** Set or clear the user-friendly label for a document. */
    public static void setDocumentLabel(Context context, String docId, String label)
    {
        if (docId == null) return;
        SharedPreferences.Editor ed = context
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
        if (label == null || label.isEmpty())
            ed.remove(docKey(SUFFIX_LABEL, docId));
        else
            ed.putString(docKey(SUFFIX_LABEL, docId), label);
        ed.apply();
    }

    /**
     * Append {@code newDocId} to the document-ID list (idempotent — does
     * nothing if already present) and persist.
     */
    private static void appendToDocIdList(Context context, String newDocId)
    {
        List<String> ids = getDocumentIds(context);
        if (ids.contains(newDocId)) return;
        ids.add(newDocId);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ids.size(); i++)
        {
            if (i > 0) sb.append(',');
            sb.append(ids.get(i));
        }
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putString(KEY_DOC_IDS, sb.toString()).apply();
    }

    /**
     * Remove {@code docId} from the document-ID list. Caller is responsible
     * for clearing the per-doc keys separately.
     */
    private static void removeFromDocIdList(Context context, String docId)
    {
        List<String> ids = getDocumentIds(context);
        if (!ids.remove(docId)) return;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ids.size(); i++)
        {
            if (i > 0) sb.append(',');
            sb.append(ids.get(i));
        }
        SharedPreferences.Editor ed = context
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
        ed.putString(KEY_DOC_IDS, sb.toString());
        // Update current pointer if the removed doc was the current one.
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String current = prefs.getString(KEY_CURRENT_DOC_ID, "");
        if (current.equals(docId))
            ed.putString(KEY_CURRENT_DOC_ID, ids.isEmpty() ? "" : ids.get(0));
        ed.apply();
    }

    /**
     * Mint a new document slot with a fresh issuer keypair. The slot starts
     * empty (no elements). Use {@link #addAccessElement(Context, byte[], String, String, int, AccessDocConfig)}
     * to populate it. The new docId becomes the current document.
     *
     * @param label optional user-friendly name; defaults to "Document N"
     * @return the new docId, or null on failure
     */
    public static String createNewDocument(Context context, String label)
    {
        try
        {
            migrateLegacyIfNeeded(context);
            // Generate a fresh issuer keypair for THIS document. The keypair
            // is what makes the document distinct from every other stored doc
            // — its kid is derived from the public key, and that kid is what
            // the reader uses to bind the document to a configured trust
            // root.
            KeyPair issuerKP = AliroCryptoProvider.generateEphemeralKeypair();
            if (issuerKP == null) return null;
            byte[] issuerPubBytes = uncompressedPoint((ECPublicKey) issuerKP.getPublic());

            String docId = allocateDocId();
            SharedPreferences.Editor ed = context
                    .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
            ed.putString(docKey(KEY_ISSUER_PUB_KEY,  docId), Hex.toHexString(issuerPubBytes));
            ed.putString(docKey(KEY_ISSUER_PRIV_KEY, docId),
                         Hex.toHexString(issuerKP.getPrivate().getEncoded()));
            ed.putString(docKey(KEY_ELEMENT_IDS, docId), "");
            ed.putString(docKey(KEY_DOC_MODE,    docId), "empty");
            ed.putString(docKey(KEY_DOC_VALID_FROM, docId), Instant.now().toString());
            ed.putString(KEY_CURRENT_DOC_ID, docId);
            if (label != null && !label.isEmpty())
                ed.putString(docKey(SUFFIX_LABEL, docId), label);
            ed.apply();
            appendToDocIdList(context, docId);

            Log.i(TAG, "createNewDocument: created docId=" + docId
                    + " issuerKid=" + computeKidHex(issuerPubBytes));
            return docId;
        }
        catch (Exception e)
        {
            Log.e(TAG, "createNewDocument failed", e);
            return null;
        }
    }

    /**
     * Compute the hex-encoded SHA-256(0x"key-identifier" || issuerPubKey)
     * truncated to 8 bytes — the standard Aliro IssuerAuth kid (§7.2.1).
     * Returned as a 16-char lowercase hex string for log/UI display.
     */
    private static String computeKidHex(byte[] issuerPubBytes)
    {
        try
        {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update("key-identifier".getBytes());
            sha.update(issuerPubBytes);
            byte[] digest = sha.digest();
            return Hex.toHexString(Arrays.copyOfRange(digest, 0, 8));
        }
        catch (Exception e)
        {
            return "????????";
        }
    }

    /** Delete a stored document and everything keyed under it. Idempotent. */
    public static void removeDocument(Context context, String docId)
    {
        if (docId == null) return;
        migrateLegacyIfNeeded(context);
        SharedPreferences.Editor ed = context
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
        // Clear every per-doc key we know about.
        ed.remove(docKey(KEY_ACCESS_DOC,             docId));
        ed.remove(docKey(KEY_ISSUER_PUB_KEY,         docId));
        ed.remove(docKey(KEY_ISSUER_PRIV_KEY,        docId));
        ed.remove(docKey(KEY_ELEMENT_ID,             docId));
        ed.remove(docKey(KEY_ELEMENT_IDS,            docId));
        ed.remove(docKey(KEY_DOC_MODE,               docId));
        ed.remove(docKey(KEY_DOC_VALID_FROM,         docId));
        ed.remove(docKey(KEY_DOC_VALID_UNTIL,        docId));
        ed.remove(docKey(SUFFIX_LABEL,               docId));
        ed.remove(docKey(KEY_REVOC_DOC,              docId));
        ed.remove(docKey(KEY_REVOC_ISSUER_PUB_KEY,   docId));
        ed.remove(docKey(KEY_REVOC_ISSUER_PRIV_KEY,  docId));
        ed.remove(docKey(KEY_REVOC_ELEMENT_ID,       docId));
        ed.remove(docKey(KEY_REVOC_ELEMENT_IDS,      docId));
        ed.apply();
        removeFromDocIdList(context, docId);
        Log.i(TAG, "removeDocument: deleted docId=" + docId);
    }

    /**
     * Get the stored DeviceResponse bytes for a specific document, or null
     * if that document has no Access Document yet (newly minted slot).
     */
    public static byte[] getDocumentBytes(Context context, String docId)
    {
        if (docId == null) return null;
        migrateLegacyIfNeeded(context);
        String b64 = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(docKey(KEY_ACCESS_DOC, docId), null);
        if (b64 == null || b64.isEmpty()) return null;
        try { return Base64.decode(b64, Base64.DEFAULT); }
        catch (Exception e) { return null; }
    }

    /**
     * Get the stored Revocation DeviceResponse bytes for a specific
     * document, or null if absent.
     */
    public static byte[] getRevocationDocumentBytesFor(Context context, String docId)
    {
        if (docId == null) return null;
        migrateLegacyIfNeeded(context);
        String b64 = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(docKey(KEY_REVOC_DOC, docId), null);
        if (b64 == null || b64.isEmpty()) return null;
        try { return Base64.decode(b64, Base64.DEFAULT); }
        catch (Exception e) { return null; }
    }

    /** List of element identifiers carried in the named document's Access side. */
    public static List<String> getElementIdentifiers(Context context, String docId)
    {
        List<String> out = new ArrayList<>();
        if (docId == null) return out;
        migrateLegacyIfNeeded(context);
        String csv = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(docKey(KEY_ELEMENT_IDS, docId), "");
        if (!csv.isEmpty())
        {
            for (String s : csv.split(","))
            {
                String t = s.trim();
                if (!t.isEmpty()) out.add(t);
            }
        }
        return out;
    }

    /**
     * Read the stored {@link AccessDocConfig} for a single element of the
     * named document by parsing its persisted AccessData CBOR. Returns
     * {@code null} if the document or element cannot be found or the
     * AccessData shape is unrecognized.
     *
     * <p>Used by the Edit Element flow: when the user picks an existing
     * element, the form repopulates with that element's current employee
     * id + matching SchedulePreset so they can tweak it. Saving (the
     * existing "Add Element" path with the same element id) reuses the
     * document's issuer keypair and replaces the entry in place — kid
     * stays stable per Aliro 1.0 §7.3.
     *
     * <p>The schedule preset is recovered by fingerprinting the AccessData's
     * Schedules array against each {@link SchedulePreset} variant. Any
     * AccessData shape that doesn't match a known preset (e.g. an imported
     * document or a future variant) returns null, which the UI surfaces as
     * "could not infer preset — pick one to overwrite".
     */
    public static AccessDocConfig getElementConfig(Context context,
                                                    String docId,
                                                    String elementId)
    {
        if (context == null || docId == null || elementId == null) return null;
        try
        {
            byte[] docBytes = getDocumentBytes(context, docId);
            if (docBytes == null) return null;
            List<ElementEntry> entries = extractAllElements(docBytes, NAMESPACE_ACCESS);
            for (ElementEntry e : entries)
            {
                if (!e.elementId.equals(elementId)) continue;
                CBORObject ad = e.accessData;
                if (ad == null) return null;

                // AccessData.id (key 1) is a UTF-8 byte string per Table 7-5
                String employeeId = "";
                CBORObject idObj = ad.get(CBORObject.FromObject(1));
                if (idObj != null)
                {
                    if (idObj.getType() == com.upokecenter.cbor.CBORType.ByteString)
                    {
                        employeeId = new String(idObj.GetByteString(),
                                java.nio.charset.StandardCharsets.UTF_8);
                    }
                    else if (idObj.getType() == com.upokecenter.cbor.CBORType.TextString)
                    {
                        employeeId = idObj.AsString();
                    }
                }

                SchedulePreset preset = inferPresetFromAccessData(ad);
                if (preset == null)
                {
                    Log.d(TAG, "getElementConfig: could not fingerprint preset for '"
                            + elementId + "' — caller will need to pick one");
                    // Fall back to WEEKDAY_AND_WEEKEND so the user at least
                    // has a sensible default selected; saving will overwrite
                    // the schedules with the chosen preset.
                    preset = SchedulePreset.WEEKDAY_AND_WEEKEND;
                }
                return new AccessDocConfig(elementId, employeeId, preset);
            }
        }
        catch (Exception ex)
        {
            Log.w(TAG, "getElementConfig failed: " + ex.getMessage());
        }
        return null;
    }

    /**
     * Match an AccessData CBOR map against the known {@link SchedulePreset}
     * fingerprints. Each preset emits a distinctive Schedules array shape
     * (count + dayMask + duration + time-of-day anchor); we don't need to
     * compare bytes exactly because endPeriods are allowed to diverge between
     * legacy/far-future variants. Returns null when no preset matches.
     */
    private static SchedulePreset inferPresetFromAccessData(CBORObject accessData)
    {
        try
        {
            CBORObject schedules = accessData.get(CBORObject.FromObject(3));
            if (schedules == null
                    || schedules.getType() != com.upokecenter.cbor.CBORType.Array)
                return null;
            int n = schedules.size();
            if (n == 1)
            {
                long todStart  = scheduleTodStart(schedules.get(0));
                long duration  = scheduleDuration(schedules.get(0));
                int  dayMask   = scheduleDayMask(schedules.get(0));
                if (dayMask == 0x7F && duration == 86400L && todStart == 0L)
                    return SchedulePreset.ALWAYS_ALLOW_24X7;
                if (dayMask == 0x1F && duration == 16L * 3600L && todStart == 21600L)
                    return SchedulePreset.WEEKDAY_EXTENDED;
                if (dayMask == 0x60 && duration == 86400L && todStart == 0L)
                    return SchedulePreset.WEEKEND_24H;
                if (dayMask == 0x1F && duration == 8L * 3600L  && todStart == 79200L)
                    return SchedulePreset.NIGHT_SHIFT;
            }
            else if (n == 2)
            {
                int  m0 = scheduleDayMask(schedules.get(0));
                long d0 = scheduleDuration(schedules.get(0));
                long t0 = scheduleTodStart(schedules.get(0));
                int  m1 = scheduleDayMask(schedules.get(1));
                long d1 = scheduleDuration(schedules.get(1));
                long t1 = scheduleTodStart(schedules.get(1));
                if (m0 == 0x1F && d0 == 12L * 3600L && t0 == 25200L
                        && m1 == 0x60 && d1 == 8L * 3600L  && t1 == 32400L)
                    return SchedulePreset.WEEKDAY_AND_WEEKEND;
            }
        }
        catch (Exception ignored) { /* fall through */ }
        return null;
    }

    /** Read recurrenceRule[0] (durationSeconds) from a Schedule entry. */
    private static long scheduleDuration(CBORObject schedule)
    {
        CBORObject rec = schedule.get(CBORObject.FromObject(2));
        if (rec == null || rec.getType() != com.upokecenter.cbor.CBORType.Array
                || rec.size() < 1) return -1L;
        return rec.get(0).AsInt64();
    }

    /** Read recurrenceRule[1] (dayMask) from a Schedule entry. */
    private static int scheduleDayMask(CBORObject schedule)
    {
        CBORObject rec = schedule.get(CBORObject.FromObject(2));
        if (rec == null || rec.getType() != com.upokecenter.cbor.CBORType.Array
                || rec.size() < 2) return -1;
        return rec.get(1).AsInt32();
    }

    /** Read startPeriod (key 0) % 86400 — i.e. the time-of-day anchor — from a Schedule entry. */
    private static long scheduleTodStart(CBORObject schedule)
    {
        CBORObject sp = schedule.get(CBORObject.FromObject(0));
        if (sp == null) return -1L;
        return sp.AsInt64() % 86400L;
    }

    /** List of element identifiers carried in the named document's Revocation side. */
    public static List<String> getRevocationElementIdentifiers(Context context, String docId)
    {
        List<String> out = new ArrayList<>();
        if (docId == null) return out;
        migrateLegacyIfNeeded(context);
        String csv = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(docKey(KEY_REVOC_ELEMENT_IDS, docId), "");
        if (!csv.isEmpty())
        {
            for (String s : csv.split(","))
            {
                String t = s.trim();
                if (!t.isEmpty()) out.add(t);
            }
        }
        return out;
    }

    /** Issuer public key (uncompressed 65 bytes hex) for a specific stored document. */
    public static String getIssuerPubKeyHex(Context context, String docId)
    {
        if (docId == null) return "";
        migrateLegacyIfNeeded(context);
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(docKey(KEY_ISSUER_PUB_KEY, docId), "");
    }

    /** Validity-until ISO-8601 timestamp for a specific stored document, or "" if absent. */
    public static String getDocumentValidUntil(Context context, String docId)
    {
        if (docId == null) return "";
        migrateLegacyIfNeeded(context);
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(docKey(KEY_DOC_VALID_UNTIL, docId), "");
    }

    /** Doc mode for a specific stored document (e.g. "test", "sample", "imported"). */
    public static String getDocumentMode(Context context, String docId)
    {
        if (docId == null) return "";
        migrateLegacyIfNeeded(context);
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(docKey(KEY_DOC_MODE, docId), "");
    }

    /** Clear every stored document and all per-document state. */
    public static void clearAllDocuments(Context context)
    {
        for (String docId : getDocumentIds(context))
            removeDocument(context, docId);
        // Defensive — also nuke legacy keys in case migrateLegacyIfNeeded was
        // never run before this call.
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
                .remove(KEY_ACCESS_DOC).remove(KEY_ISSUER_PUB_KEY).remove(KEY_ISSUER_PRIV_KEY)
                .remove(KEY_ELEMENT_ID).remove(KEY_ELEMENT_IDS).remove(KEY_DOC_MODE)
                .remove(KEY_DOC_VALID_FROM).remove(KEY_DOC_VALID_UNTIL)
                .remove(KEY_REVOC_DOC).remove(KEY_REVOC_ISSUER_PUB_KEY)
                .remove(KEY_REVOC_ISSUER_PRIV_KEY).remove(KEY_REVOC_ELEMENT_ID)
                .remove(KEY_REVOC_ELEMENT_IDS).remove(KEY_DOC_IDS).remove(KEY_CURRENT_DOC_ID)
                .apply();
    }

    // -------------------------------------------------------------------------

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Generate a self-signed test Access Document.
     *
     * Creates a fresh P-256 issuer keypair, builds a minimal AccessData element
     * with the given element identifier, signs it with COSE_Sign1/ES256, and
     * stores the document in SharedPreferences.
     *
     * Also generates and stores a paired Revocation Document (aliro-r) with the
     * same elementIdentifier and validDays.
     *
     * @param context          Application context
     * @param credPubKeyBytes  65-byte uncompressed credential public key
     * @param elementIdentifier  DataElementIdentifier (e.g. "access", "administrator", "floor1")
     * @param validDays        Number of days the document should be valid (e.g. 365)
     * @return Summary string for display, or null on failure
     */
    /**
     * Generate a self-signed test Access Document with a single element in a
     * brand-new document slot (Aliro 1.0 §7.7). Each call allocates a new
     * docId with its own freshly-generated issuer keypair (separate kid),
     * leaving existing stored documents intact. The new document becomes
     * the current document.
     *
     * <p>To append more elements to <em>the same</em> document, use
     * {@link #addAccessElement(Context, byte[], String, int, AccessDocConfig)}
     * (no docId argument operates on the current document and reuses its
     * issuer keypair so kid stays stable).
     *
     * @param context          Application context
     * @param credPubKeyBytes  65-byte uncompressed credential public key
     * @param elementIdentifier  DataElementIdentifier (e.g. "access", "administrator", "floor1")
     * @param validDays        Number of days the document should be valid (e.g. 365)
     * @return Summary string for display, or null on failure
     */
    public static String generateTestDocument(Context context,
                                               byte[] credPubKeyBytes,
                                               String elementIdentifier,
                                               int validDays)
    {
        // Allocate a fresh document slot (new issuer keypair, new kid),
        // make it current, then append this element to it. Existing docs
        // are preserved.
        String newDocId = createNewDocument(context, "Test Document");
        if (newDocId == null) return null;
        AccessDocConfig cfg = new AccessDocConfig(
                elementIdentifier, "ELATEC001", SchedulePreset.WEEKDAY_AND_WEEKEND);
        return addAccessElement(context, credPubKeyBytes, newDocId,
                elementIdentifier, validDays, cfg);
    }

    /**
     * Generate a self-signed Revocation Document (DocType "aliro-r").
     *
     * Per Aliro §7.6:
     *   - DocType = "aliro-r"
     *   - Namespace = "aliro-r"
     *   - IssuerAuth SHALL NOT contain deviceKeyInfo field (no MSO key "4")
     *   - Otherwise same structure as Access Document
     *
     * @deprecated Single-element revocation flow. The multi-element pipeline
     * ({@link #addAccessElement}) now builds revocation docs through
     * rebuildRevocationDocument with a persistent revocation issuer keypair,
     * so kid stays stable across edits. Retained for source compatibility.
     *
     * @param context           Application context
     * @param elementIdentifier DataElementIdentifier (same as paired Access Document)
     * @param validDays         Number of days the document should be valid
     * @return Summary string for display, or null on failure
     */
    @Deprecated
    public static String generateRevocationDocument(Context context,
                                                     String elementIdentifier,
                                                     int validDays,
                                                     KeyPair issuerKP,
                                                     byte[] issuerPubBytes)
    {
        try
        {

            // 2. Build minimal revocation data element: { 0: 1 } (version only)
            CBORObject revocData = buildMinimalAccessData(); // { 0: 1 }

            // 3. Build IssuerSignedItem per Table 7-2
            byte[] random   = AliroCryptoProvider.generateRandom(16);
            int    digestId = 0;
            CBORObject issuerSignedItem = buildIssuerSignedItem(
                    digestId, random, elementIdentifier, revocData);

            // 4. Wrap IssuerSignedItem in CBOR tag 24 per ISO 18013-5 §8.3.2.1.2.2
            byte[] itemBytes      = issuerSignedItem.EncodeToBytes();
            CBORObject taggedItem = CBORObject.FromObjectAndTag(
                    CBORObject.FromObject(itemBytes), 24);
            // Digest is over the CBOR encoding of #6.24(bstr(IssuerSignedItem))
            // per ISO 18013-5 §9.1.2.5
            byte[] taggedItemBytes = taggedItem.EncodeToBytes();
            byte[] digest          = sha256(taggedItemBytes);

            // 5. Build MobileSecurityObject WITHOUT deviceKeyInfo (no key "4") per §7.6
            Instant now   = Instant.now();
            Instant until = now.plusSeconds((long) validDays * 86400);
            CBORObject mso = buildRevocationMSO(elementIdentifier, digestId, digest, now, until);

            // 6. COSE_Sign1 over MobileSecurityObject
            byte[] msoBytes  = mso.EncodeToBytes();
            byte[] signature = coseSign1(issuerKP.getPrivate(), msoBytes);
            if (signature == null) return null;

            // 7. Build IssuerAuth = COSE_Sign1 array (NOT wrapped in CBOR tag 18)
            CBORObject issuerAuth = buildCoseSign1(issuerPubBytes, msoBytes, signature);

            // 8. Build nameSpaces map: { "aliro-r": [#6.24(bstr(IssuerSignedItem))] }
            CBORObject nameSpaces = CBORObject.NewOrderedMap();
            CBORObject itemsArray = CBORObject.NewArray();
            itemsArray.Add(taggedItem);
            nameSpaces.Add(CBORObject.FromObject(NAMESPACE_REVOCATION), itemsArray);

            // 9. Build issuerSigned: { "1": nameSpaces, "2": IssuerAuth }
            CBORObject issuerSigned = CBORObject.NewOrderedMap();
            issuerSigned.Add(CBORObject.FromObject("1"), nameSpaces);
            issuerSigned.Add(CBORObject.FromObject("2"), issuerAuth);

            // 10. Build full document: { "1": issuerSigned, "5": docType }
            CBORObject document = CBORObject.NewOrderedMap();
            document.Add(CBORObject.FromObject("1"), issuerSigned);
            document.Add(CBORObject.FromObject("5"), CBORObject.FromObject(DOCTYPE_REVOCATION));

            // 11. Wrap in DeviceResponse: { "1": "1.0", "2": [document], "3": 0 }
            CBORObject docResponse = CBORObject.NewOrderedMap();
            docResponse.Add(CBORObject.FromObject("1"), CBORObject.FromObject("1.0"));
            CBORObject docs = CBORObject.NewArray();
            docs.Add(document);
            docResponse.Add(CBORObject.FromObject("2"), docs);
            docResponse.Add(CBORObject.FromObject("3"), CBORObject.FromObject(0));

            // 12. Store under revocation-specific keys
            byte[] cborBytes = docResponse.EncodeToBytes();
            String b64       = Base64.encodeToString(cborBytes, Base64.DEFAULT);
            String issuerHex = Hex.toHexString(issuerPubBytes);

            SharedPreferences.Editor editor = context
                    .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
            editor.putString(KEY_REVOC_DOC,            b64);
            editor.putString(KEY_REVOC_ISSUER_PUB_KEY, issuerHex);
            editor.putString(KEY_REVOC_ELEMENT_ID,     elementIdentifier);
            editor.apply();

            String summary = "Revocation Document generated.\n"
                    + "Element: " + elementIdentifier + "\n"
                    + "Valid until: " + until.toString().substring(0, 10) + "\n"
                    + "Issuer key: " + issuerHex.substring(0, 16) + "...\n"
                    + "Size: " + cborBytes.length + " bytes";
            Log.d(TAG, "Generated Revocation Document: " + cborBytes.length + " bytes");
            return summary;
        }
        catch (Exception e)
        {
            Log.e(TAG, "generateRevocationDocument failed", e);
            return null;
        }
    }

    /**
     * Generate a realistic self-signed sample Access Document simulating an employee badge.
     *
     * Builds a full AccessData element per Aliro 1.0 §7.3 including:
     *   - Employee ID "ELATEC001"
     *   - Two access rules (weekday business hours + weekend emergency)
     *   - Two schedules (Mon-Fri 07:00-19:00 UTC, Sat-Sun 09:00-17:00 UTC)
     *
     * AccessData key mapping (§7.3):
     *   0 = version, 1 = id, 2 = AccessRules, 3 = Schedules
     *
     * AccessRule key mapping (§7.3.3):
     *   0 = capabilities (bitmask: bit0=Secure, bit1=Unsecure, bit3=Momentary_Unsecure)
     *   1 = allowScheduleIds (bitmask: bit0=schedule0, bit1=schedule1)
     *
     * Schedule key mapping (§7.3.4):
     *   0 = startPeriod (unix epoch uint32), 1 = endPeriod, 2 = recurrenceRule array,
     *   3 = flags (bit0 = Time_in_UTC)
     *
     * recurrenceRule array: [durationSeconds, dayMask, pattern, interval, ordinal]
     *   pattern 2 = Weekly
     *
     * @param context          Application context
     * @param credPubKeyBytes  65-byte uncompressed credential public key
     * @param elementIdentifier  DataElementIdentifier (typically "access")
     * @param validDays        Number of days the document should be valid
     * @return Summary string for display, or null on failure
     */
    public static String generateRealisticSampleDocument(Context context,
                                                          byte[] credPubKeyBytes,
                                                          String elementIdentifier,
                                                          int validDays)
    {
        // Allocate a fresh document slot, then append the element with
        // realistic Sample data (ELATEC001 / weekday + weekend schedule).
        // Existing docs are preserved per Aliro 1.0 §7.7.
        String newDocId = createNewDocument(context, "Sample Document");
        if (newDocId == null) return null;
        AccessDocConfig cfg = new AccessDocConfig(
                elementIdentifier, "ELATEC001", SchedulePreset.WEEKDAY_AND_WEEKEND);
        return addAccessElement(context, credPubKeyBytes, newDocId,
                elementIdentifier, validDays, cfg);
    }

    /**
     * Import a pre-built Access Document from a Base64-encoded CBOR blob.
     * Validates basic CBOR structure before storing.
     *
     * @param context      Application context
     * @param base64Cbor   Base64-encoded CBOR DeviceResponse
     * @param issuerPubHex 130-char hex of issuer public key (for reader verification)
     * @return Summary string, or null on failure
     */
    public static String importDocument(Context context,
                                         String base64Cbor,
                                         String issuerPubHex)
    {
        try
        {
            byte[] cborBytes = Base64.decode(base64Cbor.trim(), Base64.DEFAULT);

            // Basic validation: must parse as CBOR map
            CBORObject doc = CBORObject.DecodeFromBytes(cborBytes);
            if (doc.getType() != com.upokecenter.cbor.CBORType.Map)
            {
                return null;
            }

            // Extract element identifiers from EVERY IssuerSignedItem in the
            // imported document's nameSpaces[aliro-a] array. Per Aliro 1.0
            // §7.3, all elements share one IssuerAuth, so a single imported
            // document may carry multiple elements. Persisting only the first
            // element ID (legacy behavior) made any extra elements unreachable
            // through the matching engine in
            // Aliro_HostApduService.buildDeviceResponse, since that engine
            // looks up element IDs from KEY_ELEMENT_IDS.
            String allElementIdsCsv = extractAllElementIds(doc);
            String validUntil       = extractValidUntil(doc);

            // Allocate a new document slot for the import — preserves any
            // existing stored docs.
            String docId = allocateDocId();
            SharedPreferences.Editor editor = context
                    .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
            editor.putString(docKey(KEY_ACCESS_DOC,      docId), base64Cbor.trim());
            editor.putString(docKey(KEY_ISSUER_PUB_KEY,  docId),
                    issuerPubHex != null ? issuerPubHex.toLowerCase().trim() : "");
            // Store the FULL CSV of element identifiers (one entry per
            // IssuerSignedItem). getAllDocuments() reads this CSV back via
            // getElementIdentifiers(context, docId) and emits one
            // StoredDocument per (docId, elementId) pair, sliced to that
            // single element. Persisting all of them is what makes a
            // multi-element imported document fully reachable from the
            // matching engine — not just its first element. Per §8.4.2:
            // "It is RECOMMENDED to return all data elements that are
            // requested and present."
            editor.putString(docKey(KEY_ELEMENT_IDS,     docId), allElementIdsCsv);
            editor.putString(docKey(KEY_DOC_MODE,        docId), "imported");
            editor.putString(docKey(KEY_DOC_VALID_FROM,  docId), "");
            editor.putString(docKey(KEY_DOC_VALID_UNTIL, docId), validUntil != null ? validUntil : "");
            editor.putString(docKey(SUFFIX_LABEL,        docId), "Imported Document");
            editor.apply();
            appendToDocIdList(context, docId);
            setCurrentDocumentId(context, docId);

            // Count elements for the summary so the user can see at a glance
            // whether they imported a single-element or multi-element doc.
            int elementCount = allElementIdsCsv.isEmpty()
                    ? 0
                    : allElementIdsCsv.split(",").length;

            String summary = "Document imported.\n"
                    + "Element" + (elementCount == 1 ? "" : "s")
                    + " (" + elementCount + "): "
                    + (allElementIdsCsv.isEmpty() ? "(unknown)" : allElementIdsCsv) + "\n"
                    + "Valid until: " + (validUntil != null ? validUntil : "(unknown)") + "\n"
                    + "Size: " + cborBytes.length + " bytes";
            Log.d(TAG, "Imported Access Document: " + cborBytes.length
                    + " bytes (docId=" + docId
                    + ", elements=[" + allElementIdsCsv + "])");
            return summary;
        }
        catch (Exception e)
        {
            Log.e(TAG, "importDocument failed", e);
            return null;
        }
    }

    /**
     * Clear the *current* stored Access Document. If multiple documents are
     * stored, this removes only the currently-selected one. To wipe every
     * stored document, use {@link #clearAllDocuments(Context)}.
     */
    public static void clearDocument(Context context)
    {
        String docId = getCurrentDocumentId(context);
        if (docId != null)
        {
            removeDocument(context, docId);
            Log.d(TAG, "Access Document cleared (docId=" + docId + ")");
        }
    }

    /**
     * Clear the Revocation half of the *current* document. The Access half
     * is left intact, so this is a partial clear used for testing the
     * "no revocation" signaling case.
     */
    public static void clearRevocationDocument(Context context)
    {
        String docId = getCurrentDocumentId(context);
        if (docId == null) return;
        SharedPreferences.Editor ed = context
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
        ed.remove(docKey(KEY_REVOC_DOC,             docId));
        ed.remove(docKey(KEY_REVOC_ISSUER_PUB_KEY,  docId));
        ed.remove(docKey(KEY_REVOC_ISSUER_PRIV_KEY, docId));
        ed.remove(docKey(KEY_REVOC_ELEMENT_ID,      docId));
        ed.remove(docKey(KEY_REVOC_ELEMENT_IDS,     docId));
        ed.apply();
        Log.d(TAG, "Revocation Document cleared (docId=" + docId + ")");
    }

    /**
     * Check whether an Access Document is currently stored. Returns true if
     * the current document has bytes; false otherwise.
     */
    public static boolean hasDocument(Context context)
    {
        return getDocumentBytes(context) != null;
    }

    /**
     * Check whether ANY stored document has a Revocation Document companion.
     * Used by the credential's HCE to set the signaling bitmap — the reader
     * needs to know if a revocation doc is available before requesting it.
     */
    public static boolean hasRevocationDocument(Context context)
    {
        for (String docId : getDocumentIds(context))
        {
            if (getRevocationDocumentBytesFor(context, docId) != null) return true;
        }
        return false;
    }

    /**
     * Get the stored Access Document CBOR bytes for the *current* document,
     * or null if no documents are stored. Equivalent to
     * {@code getDocumentBytes(ctx, getCurrentDocumentId(ctx))}.
     */
    public static byte[] getDocumentBytes(Context context)
    {
        return getDocumentBytes(context, getCurrentDocumentId(context));
    }

    /**
     * Get the stored Revocation Document CBOR bytes for the *current*
     * document, or null. The HCE service uses {@link #getAllDocuments} to
     * walk every stored doc when matching a reader's docType=aliro-r
     * request, so this no-arg version is mainly used by Config UI status.
     */
    public static byte[] getRevocationDocumentBytes(Context context)
    {
        return getRevocationDocumentBytesFor(context, getCurrentDocumentId(context));
    }

    /**
     * Get the *first* element identifier of the current document, or
     * "access" if no document is stored. Preserved for callers that haven't
     * been updated to query the multi-element list.
     */
    public static String getElementIdentifier(Context context)
    {
        List<String> ids = getElementIdentifiers(context);
        return ids.isEmpty() ? "access" : ids.get(0);
    }

    /**
     * Get the *first* revocation element identifier of the current
     * document, or "access" if none is stored.
     */
    public static String getRevocationElementIdentifier(Context context)
    {
        List<String> ids = getRevocationElementIdentifiers(context);
        return ids.isEmpty() ? "access" : ids.get(0);
    }

    /**
     * Get the issuer public key (65-byte uncompressed) for the *current*
     * document, or null if none stored.
     */
    public static byte[] getIssuerPublicKeyBytes(Context context)
    {
        String hex = getIssuerPubKeyHex(context, getCurrentDocumentId(context));
        if (hex == null || hex.isEmpty()) return null;
        try { return Hex.decode(hex); }
        catch (Exception e) { return null; }
    }

    // =========================================================================
    // Multi-element API (Aliro 1.0 §7.3 — multiple IssuerSignedItems per doc)
    // =========================================================================

    /**
     * Get the list of element identifiers in the *current* document's
     * Access side. Returns an empty list if no document is stored.
     *
     * <p>Per Aliro §7.3, an Access Document's nameSpaces["aliro-a"] is an
     * array of IssuerSignedItems, each carrying its own elementIdentifier.
     * This returns every element present in the current stored document,
     * in document order.
     */
    public static List<String> getElementIdentifiers(Context context)
    {
        return getElementIdentifiers(context, getCurrentDocumentId(context));
    }

    // -------------------------------------------------------------------------
    // v11: Per-element document view of the stored multi-element Access Document
    //
    // The on-disk format is one DeviceResponse per kind (access / revocation)
    // containing N IssuerSignedItems sharing one IssuerAuth, per Aliro 1.0 §7.3.
    // Several v11 call sites (Aliro_HostApduService.handleAuth1 signaling
    // bitmap, buildDeviceResponse element matching) need a per-element list
    // rather than the raw aggregate document. getAllDocuments() slices the
    // aggregate into N StoredDocument entries, one per elementId, where each
    // entry's accessDocBytes is itself a valid DeviceResponse carrying just
    // that element. This is also a valid wire shape — multi-item to single-
    // item slicing preserves the IssuerAuth signature because the MSO's
    // valueDigests still covers every digest, and the verifier only checks
    // digests for items it actually receives (§7.2 Step 8).
    // -------------------------------------------------------------------------

    /**
     * Per-element view of the stored Access (and matching Revocation) Document.
     * One StoredDocument is produced for each element identifier present in
     * the credential's stored multi-element document.
     *
     * <p>{@code accessDocBytes} and {@code revocationDocBytes} are each
     * stand-alone DeviceResponse byte arrays containing exactly one document
     * with a single IssuerSignedItem in its namespace, sharing the parent
     * IssuerAuth. Either may be null/empty when the corresponding kind is
     * not provisioned.
     */
    public static class StoredDocument
    {
        /** DataElementIdentifier (e.g. "floor1", "access"). Never null. */
        public final String elementId;

        /**
         * Stand-alone DeviceResponse for this element's Access Document, or
         * null if no Access Document is stored.
         */
        public final byte[] accessDocBytes;

        /**
         * Stand-alone DeviceResponse for this element's Revocation Document,
         * or null if no Revocation Document is stored.
         */
        public final byte[] revocationDocBytes;

        public StoredDocument(String elementId,
                              byte[] accessDocBytes,
                              byte[] revocationDocBytes)
        {
            this.elementId          = elementId;
            this.accessDocBytes     = accessDocBytes;
            this.revocationDocBytes = revocationDocBytes;
        }
    }

    /**
     * Return a per-element view across <em>every</em> stored Access Document
     * (Aliro 1.0 §7.7).
     *
     * <p>For each element identifier in each stored document, produces a
     * StoredDocument whose {@code accessDocBytes} is a single-element
     * DeviceResponse slice from <em>that</em> document — signed by
     * <em>that</em> document's own issuer keypair, with <em>that</em>
     * document's own kid. The matching revocation slice is produced
     * similarly from the same document's revocation half.
     *
     * <p>{@code Aliro_HostApduService.buildDeviceResponse} treats this
     * flat list as the universe of available elements when matching a
     * reader's DeviceRequest. If the reader requests {@code floor1}
     * (which lives in document A) and {@code gym_locker_5} (which lives
     * in document B), the credential returns one Document for each — each
     * signed by its own issuer — and the reader verifies each against the
     * matching trusted issuer key.
     *
     * <p>Returns an empty list when no documents are stored. Never returns
     * null. The same {@code elementId} appearing in two different stored
     * documents will produce two entries; that's a real-world case (e.g.
     * personal-life "access" + work "access" elements with different
     * issuers) that the §7.7 layout supports.
     */
    public static List<StoredDocument> getAllDocuments(Context context)
    {
        List<StoredDocument> out = new ArrayList<>();
        try
        {
            for (String docId : getDocumentIds(context))
            {
                byte[] accessDocBytes = getDocumentBytes(context, docId);
                byte[] revocDocBytes  = getRevocationDocumentBytesFor(context, docId);

                // Per-doc element-id lists. The union covers the case where
                // access and revocation halves diverge (only access-side
                // elements are usable for Step-Up; revocation-only elements
                // exist for the §7.6 revocation flow).
                List<String> accessIds = getElementIdentifiers(context, docId);
                List<String> revocIds  = getRevocationElementIdentifiers(context, docId);

                java.util.LinkedHashSet<String> allIds = new java.util.LinkedHashSet<>();
                allIds.addAll(accessIds);
                allIds.addAll(revocIds);

                for (String elementId : allIds)
                {
                    byte[] accessSlice = (accessDocBytes != null && accessIds.contains(elementId))
                            ? sliceDocumentForElement(accessDocBytes, NAMESPACE_ACCESS, elementId)
                            : null;
                    byte[] revocSlice = (revocDocBytes != null && revocIds.contains(elementId))
                            ? sliceDocumentForElement(revocDocBytes, NAMESPACE_REVOCATION, elementId)
                            : null;
                    if (accessSlice != null || revocSlice != null)
                    {
                        out.add(new StoredDocument(elementId, accessSlice, revocSlice));
                    }
                }
            }
        }
        catch (Exception e)
        {
            Log.w(TAG, "getAllDocuments failed: " + e.getMessage());
        }
        return out;
    }

    /**
     * Get the list of element identifiers present in the *current*
     * document's Revocation side, mirroring
     * {@link #getElementIdentifiers(Context)} for the revocation side.
     */
    public static List<String> getRevocationElementIdentifiers(Context context)
    {
        return getRevocationElementIdentifiers(context, getCurrentDocumentId(context));
    }

    /**
     * Slice an aggregate DeviceResponse (one document containing N
     * IssuerSignedItems) down to a stand-alone DeviceResponse containing only
     * the matching element. The IssuerAuth, version, status, and docType are
     * all preserved unchanged so the resulting bytes verify against the
     * issuer key the same way the aggregate did.
     *
     * @return the sliced DeviceResponse bytes, or null if the requested
     *         element isn't present or the source can't be parsed
     */
    private static byte[] sliceDocumentForElement(byte[] aggregateBytes,
                                                   String namespaceName,
                                                   String elementIdentifier)
    {
        try
        {
            CBORObject deviceResponse = CBORObject.DecodeFromBytes(aggregateBytes);
            CBORObject docs           = deviceResponse.get(CBORObject.FromObject("2"));
            if (docs == null || docs.size() == 0) return null;

            CBORObject doc      = docs.get(0);
            CBORObject iSigned  = doc.get(CBORObject.FromObject("1"));
            if (iSigned == null) return null;
            CBORObject ns       = iSigned.get(CBORObject.FromObject("1"));
            if (ns == null) return null;
            CBORObject items    = ns.get(CBORObject.FromObject(namespaceName));
            if (items == null || items.size() == 0) return null;

            // Find the tagged item whose decoded inner has elementIdentifier == requested.
            CBORObject matchingTaggedItem = null;
            for (int i = 0; i < items.size(); i++)
            {
                CBORObject taggedItem = items.get(i);
                byte[] itemBytes;
                if (taggedItem.isTagged()
                        && taggedItem.getMostOuterTag().ToInt32Checked() == 24)
                {
                    itemBytes = taggedItem.GetByteString();
                }
                else if (taggedItem.getType() == com.upokecenter.cbor.CBORType.ByteString)
                {
                    itemBytes = taggedItem.GetByteString();
                }
                else
                {
                    continue;
                }
                CBORObject inner = CBORObject.DecodeFromBytes(itemBytes);
                CBORObject eid   = inner.get(CBORObject.FromObject("3"));
                if (eid != null && elementIdentifier.equals(eid.AsString()))
                {
                    matchingTaggedItem = taggedItem;
                    break;
                }
            }
            if (matchingTaggedItem == null) return null;

            // Build single-item items array.
            CBORObject singleItems = CBORObject.NewArray();
            singleItems.Add(matchingTaggedItem);

            // Rebuild nameSpaces with just that single item.
            CBORObject newNameSpaces = CBORObject.NewOrderedMap();
            newNameSpaces.Add(CBORObject.FromObject(namespaceName), singleItems);

            // Rebuild issuerSigned: keep IssuerAuth (key "2") unchanged.
            CBORObject newIssuerSigned = CBORObject.NewOrderedMap();
            newIssuerSigned.Add(CBORObject.FromObject("1"), newNameSpaces);
            CBORObject issuerAuth = iSigned.get(CBORObject.FromObject("2"));
            if (issuerAuth != null)
                newIssuerSigned.Add(CBORObject.FromObject("2"), issuerAuth);

            // Rebuild document: preserve docType (key "5") if present.
            CBORObject newDoc = CBORObject.NewOrderedMap();
            newDoc.Add(CBORObject.FromObject("1"), newIssuerSigned);
            CBORObject docType = doc.get(CBORObject.FromObject("5"));
            if (docType != null)
                newDoc.Add(CBORObject.FromObject("5"), docType);

            // Rebuild DeviceResponse: preserve version (key "1") and status (key "3").
            CBORObject newResponse = CBORObject.NewOrderedMap();
            CBORObject version = deviceResponse.get(CBORObject.FromObject("1"));
            if (version != null)
                newResponse.Add(CBORObject.FromObject("1"), version);
            CBORObject newDocs = CBORObject.NewArray();
            newDocs.Add(newDoc);
            newResponse.Add(CBORObject.FromObject("2"), newDocs);
            CBORObject status = deviceResponse.get(CBORObject.FromObject("3"));
            if (status != null)
                newResponse.Add(CBORObject.FromObject("3"), status);

            return newResponse.EncodeToBytes();
        }
        catch (Exception e)
        {
            Log.w(TAG, "sliceDocumentForElement failed for '" + elementIdentifier
                    + "': " + e.getMessage());
            return null;
        }
    }

    /**
     * Add (or replace) an element in the stored Access Document.
     *
     * Behavior:
     *   - If no document is currently stored, generates a fresh issuer keypair
     *     and creates a new document containing this single element. Also
     *     generates a paired Revocation Document with a fresh revocation issuer
     *     keypair.
     *   - If a document is already stored, loads its persisted issuer keypair
     *     and rebuilds the document with this element appended (or replacing the
     *     same-named element). The kid stays stable because the issuer keypair
     *     is reused. The Revocation Document is rebuilt the same way.
     *
     * Per Aliro 1.0 §7.3, all elements share one IssuerAuth (one COSE_Sign1
     * signature) over a MobileSecurityObject whose valueDigests covers every
     * IssuerSignedItem in the namespace. This is fully spec-compliant.
     *
     * @param context           Application context
     * @param credPubKeyBytes   65-byte uncompressed credential public key
     * @param elementIdentifier DataElementIdentifier (e.g. "access", "floor1")
     * @param validDays         Number of days the document should be valid
     * @param useRealisticData  true → realistic ELATEC001 employee badge data;
     *                          false → minimal { 0: 1 } version-only data
     * @return Summary string for display, or null on failure
     */
    public static String addAccessElement(Context context,
                                            byte[] credPubKeyBytes,
                                            String elementIdentifier,
                                            int validDays,
                                            boolean useRealisticData)
    {
        // Legacy overload — delegates to the AccessDocConfig-based version
        // with the historical defaults so existing call sites that haven't
        // been updated continue to produce the same bytes they did before
        // per-document content configurability was added.
        AccessDocConfig legacyCfg = new AccessDocConfig(
                elementIdentifier, "ELATEC001", SchedulePreset.WEEKDAY_AND_WEEKEND);
        return addAccessElement(context, credPubKeyBytes, elementIdentifier,
                                 validDays, legacyCfg);
    }

    /**
     * Add (or replace) an element in the stored Access Document, using the
     * supplied {@link AccessDocConfig} to populate Employee/Badge ID and
     * Schedule shape. Each added element gets its own AccessData CBOR built
     * from the config — multiple Add Element calls with different configs
     * produce visibly distinct stored elements while still sharing one
     * IssuerAuth per Aliro 1.0 §7.3.
     *
     * @param context           Application context
     * @param credPubKeyBytes   65-byte uncompressed credential public key
     * @param elementIdentifier DataElementIdentifier (e.g. "floor1"). Should
     *                          equal {@code config.name}; the explicit
     *                          parameter is retained for API symmetry with
     *                          the legacy boolean overload.
     * @param validDays         Number of days the document should be valid
     * @param config            Per-document content config (employeeId,
     *                          schedule preset). Must be non-null.
     * @return Summary string for display, or null on failure
     */
    public static String addAccessElement(Context context,
                                            byte[] credPubKeyBytes,
                                            String elementIdentifier,
                                            int validDays,
                                            AccessDocConfig config)
    {
        return addAccessElement(context, credPubKeyBytes,
                getCurrentDocumentId(context), elementIdentifier, validDays, config);
    }

    /**
     * Add (or replace) an element on the named stored Access Document.
     * If {@code docId} is null, a new document is created with a fresh
     * issuer keypair, becomes the current document, and the element is
     * added to it. Otherwise the existing document at {@code docId} is
     * extended in place (same issuer keypair, same kid).
     *
     * <p>Per Aliro 1.0 §7.3, the document keeps one IssuerAuth and grows
     * its IssuerSignedItem array — same issuer signs all elements within
     * a document. Per §7.7, separate documents may have separate issuers,
     * which is what {@link #createNewDocument} sets up.
     */
    public static String addAccessElement(Context context,
                                            byte[] credPubKeyBytes,
                                            String docId,
                                            String elementIdentifier,
                                            int validDays,
                                            AccessDocConfig config)
    {
        try
        {
            if (config == null)
            {
                Log.e(TAG, "addAccessElement: config is null");
                return null;
            }
            migrateLegacyIfNeeded(context);

            // 1. Build the AccessData payload from the per-document config.
            //    Honors Employee/Badge ID + Schedule Preset chosen in the UI.
            CBORObject accessData = buildAccessDataFromConfig(config);

            // 2. Resolve target document. If docId is null OR no docs exist
            //    yet, allocate a new slot with a fresh issuer keypair.
            KeyPair issuerKP;
            byte[]  issuerPubBytes;
            List<ElementEntry> entries;
            String docMode;
            boolean newlyCreated = false;

            byte[] existingDocBytes = (docId != null) ? getDocumentBytes(context, docId) : null;
            KeyPair existingKP      = (docId != null) ? loadIssuerKeypair(context, docId, false) : null;

            if (docId != null && existingKP != null)
            {
                issuerKP       = existingKP;
                issuerPubBytes = uncompressedPoint((ECPublicKey) issuerKP.getPublic());
                entries        = (existingDocBytes != null)
                        ? extractAllElements(existingDocBytes, NAMESPACE_ACCESS)
                        : new ArrayList<>();
                // Replace any existing entry with the same elementId
                for (int i = 0; i < entries.size(); i++)
                {
                    if (entries.get(i).elementId.equals(elementIdentifier))
                    {
                        entries.remove(i);
                        break;
                    }
                }
                docMode = entries.isEmpty() ? "sample" : "multi";
                Log.d(TAG, "addAccessElement: docId=" + docId
                        + " reusing issuer keypair, " + entries.size() + " existing elements");
            }
            else
            {
                // Fresh start: allocate a brand-new document slot.
                String newDocId = createNewDocument(context, null);
                if (newDocId == null) return null;
                docId           = newDocId;
                issuerKP        = loadIssuerKeypair(context, docId, false);
                if (issuerKP == null)
                {
                    Log.e(TAG, "addAccessElement: createNewDocument returned id but keypair missing");
                    return null;
                }
                issuerPubBytes  = uncompressedPoint((ECPublicKey) issuerKP.getPublic());
                entries         = new ArrayList<>();
                docMode         = "sample";
                newlyCreated    = true;
                Log.d(TAG, "addAccessElement: created new docId=" + docId);
            }

            entries.add(new ElementEntry(elementIdentifier, accessData));

            // 3. Build the document with all entries and store it
            Instant now   = Instant.now();
            Instant until = now.plusSeconds((long) validDays * 86400);

            byte[] docBytes = buildAccessDocumentBytes(
                    credPubKeyBytes, entries, issuerKP, issuerPubBytes, now, until);
            if (docBytes == null) return null;

            String b64       = Base64.encodeToString(docBytes, Base64.DEFAULT);
            String issuerHex = Hex.toHexString(issuerPubBytes);

            SharedPreferences.Editor editor = context
                    .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
            editor.putString(docKey(KEY_ACCESS_DOC,       docId), b64);
            editor.putString(docKey(KEY_ISSUER_PUB_KEY,   docId), issuerHex);
            editor.putString(docKey(KEY_ISSUER_PRIV_KEY,  docId),
                    Hex.toHexString(issuerKP.getPrivate().getEncoded()));
            editor.putString(docKey(KEY_ELEMENT_IDS,      docId), joinElementIds(entries));
            editor.putString(docKey(KEY_DOC_MODE,         docId), docMode);
            editor.putString(docKey(KEY_DOC_VALID_FROM,   docId), now.toString());
            editor.putString(docKey(KEY_DOC_VALID_UNTIL,  docId), until.toString());
            editor.apply();
            // Make sure list + current pointer reflect this doc.
            appendToDocIdList(context, docId);
            setCurrentDocumentId(context, docId);

            Log.d(TAG, "addAccessElement: stored docId=" + docId + " with " + entries.size()
                    + " elements (" + docBytes.length + " bytes)");

            // 4. Rebuild paired Revocation Document for THIS doc with the
            //    same elements, signed by THIS doc's issuer key.
            String revocResult = rebuildRevocationDocument(context, docId, entries, validDays);
            if (revocResult == null)
            {
                Log.w(TAG, "addAccessElement: revocation rebuild failed (non-fatal)");
            }

            // 5. Initialize mailbox with sample data on first creation only
            if (newlyCreated)
            {
                try
                {
                    SharedPreferences mailboxPrefs = context
                            .getSharedPreferences("AliroMailbox", Context.MODE_PRIVATE);
                    String existing = mailboxPrefs.getString("mailbox", null);
                    if (existing == null || existing.isEmpty())
                    {
                        byte[] sampleMailbox = AliroMailbox.buildSampleMailbox();
                        mailboxPrefs.edit()
                                .putString("mailbox", Base64.encodeToString(sampleMailbox, Base64.DEFAULT))
                                .apply();
                        Log.d(TAG, "Initialized mailbox with sample data");
                    }
                }
                catch (Exception mbEx)
                {
                    Log.w(TAG, "Mailbox init failed (non-fatal)", mbEx);
                }
            }

            // 6. Build summary
            StringBuilder summary = new StringBuilder();
            summary.append(newlyCreated
                    ? "Document created.\n" : "Element added.\n");
            summary.append("Elements: ").append(joinElementIds(entries)).append("\n");
            summary.append("Total: ").append(entries.size()).append(" element(s)\n");
            summary.append("Valid until: ").append(until.toString().substring(0, 10)).append("\n");
            summary.append("Issuer kid: ").append(computeKidHex(issuerPubBytes)).append("\n");
            summary.append("Size: ").append(docBytes.length).append(" bytes");
            return summary.toString();
        }
        catch (Exception e)
        {
            Log.e(TAG, "addAccessElement failed", e);
            return null;
        }
    }

    /**
     * Remove a single element from the stored Access Document.
     *
     * If the removed element is the last one in the document, the document
     * (and its paired Revocation Document) is cleared entirely.
     *
     * @return Summary string for display, or null on failure / not found
     */
    public static String removeAccessElement(Context context, String elementIdentifier)
    {
        try
        {
            String docId = getCurrentDocumentId(context);
            if (docId == null)
            {
                Log.w(TAG, "removeAccessElement: no current document");
                return null;
            }
            byte[] docBytes = getDocumentBytes(context, docId);
            if (docBytes == null)
            {
                Log.w(TAG, "removeAccessElement: no document stored for docId=" + docId);
                return null;
            }
            KeyPair issuerKP = loadIssuerKeypair(context, docId, false);
            if (issuerKP == null)
            {
                Log.w(TAG, "removeAccessElement: issuer keypair not stored — cannot re-sign");
                return null;
            }

            List<ElementEntry> entries = extractAllElements(docBytes, NAMESPACE_ACCESS);
            boolean removed = false;
            for (int i = 0; i < entries.size(); i++)
            {
                if (entries.get(i).elementId.equals(elementIdentifier))
                {
                    entries.remove(i);
                    removed = true;
                    break;
                }
            }
            if (!removed)
            {
                Log.w(TAG, "removeAccessElement: element '"
                        + elementIdentifier + "' not found");
                return null;
            }

            if (entries.isEmpty())
            {
                // Last element of this document removed → remove the
                // document slot entirely (NOT the entire credential).
                removeDocument(context, docId);
                Log.d(TAG, "removeAccessElement: last element removed, docId=" + docId + " deleted");
                return "Last element removed. Document deleted.";
            }

            // Need the credential public key from the existing MSO to rebuild
            byte[] credPubKey = extractCredentialPublicKey(docBytes);
            if (credPubKey == null)
            {
                Log.e(TAG, "removeAccessElement: cannot extract credential public key");
                return null;
            }

            byte[] issuerPubBytes = uncompressedPoint((ECPublicKey) issuerKP.getPublic());

            // Reuse existing validity window to keep "Valid until" stable across edits
            SharedPreferences prefs = context
                    .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            Instant now;
            Instant until;
            try
            {
                now   = Instant.parse(prefs.getString(docKey(KEY_DOC_VALID_FROM,  docId), Instant.now().toString()));
                until = Instant.parse(prefs.getString(docKey(KEY_DOC_VALID_UNTIL, docId),
                        Instant.now().plusSeconds(365L * 86400).toString()));
            }
            catch (Exception e)
            {
                now   = Instant.now();
                until = now.plusSeconds(365L * 86400);
            }

            byte[] newDocBytes = buildAccessDocumentBytes(
                    credPubKey, entries, issuerKP, issuerPubBytes, now, until);
            if (newDocBytes == null) return null;

            prefs.edit()
                 .putString(docKey(KEY_ACCESS_DOC,  docId), Base64.encodeToString(newDocBytes, Base64.DEFAULT))
                 .putString(docKey(KEY_ELEMENT_IDS, docId), joinElementIds(entries))
                 .apply();

            // Calculate validDays from current validity window for revoc rebuild
            int validDays = (int) Math.max(1L,
                    java.time.Duration.between(now, until).toDays());
            rebuildRevocationDocument(context, docId, entries, validDays);

            return "Element '" + elementIdentifier + "' removed.\n"
                    + "Remaining: " + joinElementIds(entries);
        }
        catch (Exception e)
        {
            Log.e(TAG, "removeAccessElement failed", e);
            return null;
        }
    }

    /**
     * Refresh the validity windows of every element in the named document
     * without touching the issuer keypair.
     *
     * <p>Two distinct expirations are bumped:
     * <ul>
     *   <li>The document-level <b>validUntil</b> (MSO key 6.3 in Aliro 1.0
     *       Table 7-1) — set to {@code now + validDays} so §7.4 Step 5
     *       passes for the next {@code validDays} days.</li>
     *   <li>Each schedule's per-schedule <b>endPeriod</b> (Schedules → key
     *       1, Table 7-9-adjacent) — overwritten with
     *       {@code newScheduleEndEpoch} so §7.3.4's
     *       {@code [start, endPeriod)} window check stops failing on
     *       documents whose end was originally stamped at
     *       {@code LEGACY_END_PERIOD = 2026-04-30 00:00 UTC} for byte-identity
     *       reasons. AccessRules, Capabilities, dayMasks, durations, TOD
     *       anchors, schedule startPeriods, and Employee IDs are all
     *       preserved verbatim.</li>
     * </ul>
     *
     * <p>Per §7.3 / §7.7: the document's issuer keypair is reused, so the
     * COSE_Sign1 kid is unchanged — readers configured with the current
     * Step-Up Issuer Public Key continue to trust this document without any
     * reconfiguration. Returns a status string for UI display, or null on
     * failure.
     *
     * @param context             Application context
     * @param docId               Target document ID (must exist)
     * @param validDays           Days the refreshed document should remain
     *                            valid (drives the MSO validUntil)
     * @param newScheduleEndEpoch Epoch seconds to stamp into every
     *                            schedule's endPeriod field. Should be far
     *                            enough in the future that subsequent
     *                            verifications don't hit the §7.3.4 cliff.
     */
    public static String refreshDocumentValidity(Context context,
                                                  String docId,
                                                  int validDays,
                                                  long newScheduleEndEpoch)
    {
        try
        {
            if (context == null || docId == null) return null;
            migrateLegacyIfNeeded(context);

            byte[] docBytes = getDocumentBytes(context, docId);
            if (docBytes == null)
            {
                Log.w(TAG, "refreshDocumentValidity: no document stored for docId=" + docId);
                return null;
            }
            KeyPair issuerKP = loadIssuerKeypair(context, docId, false);
            if (issuerKP == null)
            {
                Log.w(TAG, "refreshDocumentValidity: issuer keypair not stored — cannot re-sign");
                return null;
            }
            byte[] credPubKey = extractCredentialPublicKey(docBytes);
            if (credPubKey == null)
            {
                Log.e(TAG, "refreshDocumentValidity: cannot extract credential public key");
                return null;
            }

            // Pull every element's existing AccessData CBOR and rewrite
            // each schedule's endPeriod (key 1) in place. The Schedules
            // array lives at AccessData key 3; per-schedule keys are
            // 0=startPeriod, 1=endPeriod, 2=recurrenceRule, 3=flags.
            List<ElementEntry> entries = extractAllElements(docBytes, NAMESPACE_ACCESS);
            if (entries.isEmpty())
            {
                Log.w(TAG, "refreshDocumentValidity: no elements to refresh");
                return null;
            }

            int totalSchedulesUpdated = 0;
            for (ElementEntry entry : entries)
            {
                CBORObject ad = entry.accessData;
                if (ad == null) continue;
                CBORObject schedules = ad.get(CBORObject.FromObject(3));
                if (schedules == null
                        || schedules.getType() != com.upokecenter.cbor.CBORType.Array)
                    continue;
                for (int s = 0; s < schedules.size(); s++)
                {
                    CBORObject schedule = schedules.get(s);
                    if (schedule == null
                            || schedule.getType() != com.upokecenter.cbor.CBORType.Map)
                        continue;
                    schedule.Set(CBORObject.FromObject(1),
                            CBORObject.FromObject(newScheduleEndEpoch));
                    totalSchedulesUpdated++;
                }
            }
            Log.d(TAG, "refreshDocumentValidity: updated " + totalSchedulesUpdated
                    + " schedule(s) across " + entries.size() + " element(s)");

            // Bump document-level validity window
            Instant now   = Instant.now();
            Instant until = now.plusSeconds((long) validDays * 86400);

            byte[] issuerPubBytes = uncompressedPoint((ECPublicKey) issuerKP.getPublic());
            byte[] newDocBytes = buildAccessDocumentBytes(
                    credPubKey, entries, issuerKP, issuerPubBytes, now, until);
            if (newDocBytes == null)
            {
                Log.e(TAG, "refreshDocumentValidity: buildAccessDocumentBytes returned null");
                return null;
            }

            SharedPreferences.Editor editor = context
                    .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
            editor.putString(docKey(KEY_ACCESS_DOC,      docId),
                    Base64.encodeToString(newDocBytes, Base64.DEFAULT));
            editor.putString(docKey(KEY_DOC_VALID_FROM,  docId), now.toString());
            editor.putString(docKey(KEY_DOC_VALID_UNTIL, docId), until.toString());
            editor.apply();

            // Rebuild the paired Revocation Document so its validity tracks
            // the Access Document's. Uses the same docId's revoc keypair so
            // its kid is also stable.
            rebuildRevocationDocument(context, docId, entries, validDays);

            String label = getDocumentLabel(context, docId);
            return "Refreshed '" + label + "' (" + entries.size() + " element(s), "
                    + totalSchedulesUpdated + " schedule(s)). Issuer keypair preserved — "
                    + "no reader changes needed.";
        }
        catch (Exception e)
        {
            Log.e(TAG, "refreshDocumentValidity failed", e);
            return null;
        }
    }

    // =========================================================================
    // Internal: keypair persistence
    // =========================================================================

    /**
     * Legacy convenience: load the issuer keypair for the *current* document.
     * Returns null if there is no current document or its keypair is missing.
     * Equivalent to {@code loadIssuerKeypair(context, getCurrentDocumentId(ctx), isRevoc)}.
     */
    private static KeyPair loadIssuerKeypair(Context context, boolean isRevoc)
    {
        return loadIssuerKeypair(context, getCurrentDocumentId(context), isRevoc);
    }

    /**
     * Load the persisted issuer keypair for either the Access (isRevoc=false)
     * or Revocation (isRevoc=true) document, scoped to a specific {@code docId}.
     * Returns null if not stored, if {@code docId} is null, or if
     * reconstruction fails.
     */
    private static KeyPair loadIssuerKeypair(Context context, String docId, boolean isRevoc)
    {
        if (docId == null) return null;
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String privHex = prefs.getString(
                docKey(isRevoc ? KEY_REVOC_ISSUER_PRIV_KEY : KEY_ISSUER_PRIV_KEY, docId), null);
        String pubHex  = prefs.getString(
                docKey(isRevoc ? KEY_REVOC_ISSUER_PUB_KEY  : KEY_ISSUER_PUB_KEY,  docId), null);
        if (privHex == null || privHex.isEmpty()
                || pubHex == null || pubHex.isEmpty())
        {
            return null;
        }
        try
        {
            byte[] privBytes = Hex.decode(privHex);
            byte[] pubBytes  = Hex.decode(pubHex);

            KeyFactory kf = KeyFactory.getInstance("EC");
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));

            // Reconstruct ECPublicKey from uncompressed point using the curve params
            // already attached to the private key.
            java.security.interfaces.ECPrivateKey ecPriv =
                    (java.security.interfaces.ECPrivateKey) priv;
            ECParameterSpec params = ecPriv.getParams();

            byte[] x = Arrays.copyOfRange(pubBytes, 1, 33);
            byte[] y = Arrays.copyOfRange(pubBytes, 33, 65);
            ECPoint w = new ECPoint(new java.math.BigInteger(1, x),
                                     new java.math.BigInteger(1, y));
            PublicKey pub = kf.generatePublic(new ECPublicKeySpec(w, params));

            return new KeyPair(pub, priv);
        }
        catch (Exception e)
        {
            Log.w(TAG, "loadIssuerKeypair failed: " + e.getMessage());
            return null;
        }
    }

    // =========================================================================
    // Internal: shared document builder
    // =========================================================================

    /**
     * Holds an element identifier paired with its AccessData CBOR map.
     */
    private static class ElementEntry
    {
        final String elementId;
        final CBORObject accessData;
        ElementEntry(String id, CBORObject data) { this.elementId = id; this.accessData = data; }
    }

    private static String joinElementIds(List<ElementEntry> entries)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < entries.size(); i++)
        {
            if (i > 0) sb.append(",");
            sb.append(entries.get(i).elementId);
        }
        return sb.toString();
    }

    /**
     * Build a CBOR-encoded DeviceResponse containing one Access Document with
     * one IssuerSignedItem per element in {@code entries}, all signed by a
     * single IssuerAuth (one COSE_Sign1 over an MSO whose valueDigests covers
     * every item).
     *
     * Per Aliro 1.0 §7.3, a single Access Document MAY carry multiple elements
     * in its nameSpaces["aliro-a"] array. The MSO's valueDigests["aliro-a"]
     * holds {digestID → SHA-256(taggedItem)} for every item.
     */
    private static byte[] buildAccessDocumentBytes(byte[] credPubKeyBytes,
                                                    List<ElementEntry> entries,
                                                    KeyPair issuerKP,
                                                    byte[] issuerPubBytes,
                                                    Instant validFrom,
                                                    Instant validUntil)
    {
        try
        {
            // Build IssuerSignedItems and their digests
            CBORObject itemsArray = CBORObject.NewArray();
            CBORObject digestMap  = CBORObject.NewOrderedMap();

            for (int i = 0; i < entries.size(); i++)
            {
                ElementEntry e = entries.get(i);
                byte[] random = AliroCryptoProvider.generateRandom(16);
                CBORObject item = buildIssuerSignedItem(i, random, e.elementId, e.accessData);

                byte[] itemBytes = item.EncodeToBytes();
                CBORObject taggedItem = CBORObject.FromObjectAndTag(
                        CBORObject.FromObject(itemBytes), 24);
                byte[] taggedItemBytes = taggedItem.EncodeToBytes();
                byte[] digest = sha256(taggedItemBytes);

                itemsArray.Add(taggedItem);
                digestMap.Add(CBORObject.FromObject(i), CBORObject.FromObject(digest));
            }

            // Build MSO whose valueDigests covers ALL items
            CBORObject mso = buildMultiItemMSO(credPubKeyBytes, digestMap, validFrom, validUntil);

            byte[] msoBytes  = mso.EncodeToBytes();
            byte[] signature = coseSign1(issuerKP.getPrivate(), msoBytes);
            if (signature == null) return null;

            CBORObject issuerAuth = buildCoseSign1(issuerPubBytes, msoBytes, signature);

            CBORObject nameSpaces = CBORObject.NewOrderedMap();
            nameSpaces.Add(CBORObject.FromObject(NAMESPACE_ACCESS), itemsArray);

            CBORObject issuerSigned = CBORObject.NewOrderedMap();
            issuerSigned.Add(CBORObject.FromObject("1"), nameSpaces);
            issuerSigned.Add(CBORObject.FromObject("2"), issuerAuth);

            CBORObject document = CBORObject.NewOrderedMap();
            document.Add(CBORObject.FromObject("1"), issuerSigned);
            document.Add(CBORObject.FromObject("5"), CBORObject.FromObject(DOCTYPE_ACCESS));

            CBORObject docResponse = CBORObject.NewOrderedMap();
            docResponse.Add(CBORObject.FromObject("1"), CBORObject.FromObject("1.0"));
            CBORObject docs = CBORObject.NewArray();
            docs.Add(document);
            docResponse.Add(CBORObject.FromObject("2"), docs);
            docResponse.Add(CBORObject.FromObject("3"), CBORObject.FromObject(0));

            return docResponse.EncodeToBytes();
        }
        catch (Exception e)
        {
            Log.e(TAG, "buildAccessDocumentBytes failed", e);
            return null;
        }
    }

    /**
     * Build an Access Document MSO with valueDigests already populated for
     * multiple items. Same shape as buildMSO() but takes a pre-built digestMap.
     */
    private static CBORObject buildMultiItemMSO(byte[] credPubKeyBytes,
                                                 CBORObject digestMap,
                                                 Instant validFrom,
                                                 Instant validUntil)
    {
        CBORObject mso = CBORObject.NewOrderedMap();
        mso.Add(CBORObject.FromObject("1"), CBORObject.FromObject("1.0"));
        mso.Add(CBORObject.FromObject("2"), CBORObject.FromObject("SHA-256"));

        CBORObject valueDigests = CBORObject.NewOrderedMap();
        valueDigests.Add(CBORObject.FromObject(NAMESPACE_ACCESS), digestMap);
        mso.Add(CBORObject.FromObject("3"), valueDigests);

        CBORObject coseKey = buildCoseEcKey(credPubKeyBytes);
        CBORObject deviceKeyInfo = CBORObject.NewOrderedMap();
        deviceKeyInfo.Add(CBORObject.FromObject("1"), coseKey);
        mso.Add(CBORObject.FromObject("4"), deviceKeyInfo);

        mso.Add(CBORObject.FromObject("5"), CBORObject.FromObject(DOCTYPE_ACCESS));

        CBORObject validity = CBORObject.NewOrderedMap();
        validity.Add(CBORObject.FromObject("1"),
                CBORObject.FromObjectAndTag(validFrom.toString(), 0));
        validity.Add(CBORObject.FromObject("2"),
                CBORObject.FromObjectAndTag(validFrom.toString(), 0));
        validity.Add(CBORObject.FromObject("3"),
                CBORObject.FromObjectAndTag(validUntil.toString(), 0));
        mso.Add(CBORObject.FromObject("6"), validity);

        mso.Add(CBORObject.FromObject("7"), CBORObject.FromObject(false));
        return mso;
    }

    /**
     * Build a Revocation Document MSO whose valueDigests covers multiple items.
     */
    private static CBORObject buildMultiItemRevocationMSO(CBORObject digestMap,
                                                           Instant validFrom,
                                                           Instant validUntil)
    {
        CBORObject mso = CBORObject.NewOrderedMap();
        mso.Add(CBORObject.FromObject("1"), CBORObject.FromObject("1.0"));
        mso.Add(CBORObject.FromObject("2"), CBORObject.FromObject("SHA-256"));

        CBORObject valueDigests = CBORObject.NewOrderedMap();
        valueDigests.Add(CBORObject.FromObject(NAMESPACE_REVOCATION), digestMap);
        mso.Add(CBORObject.FromObject("3"), valueDigests);

        // Per Aliro §7.6, no key "4" (deviceKeyInfo) for revocation docs
        mso.Add(CBORObject.FromObject("5"), CBORObject.FromObject(DOCTYPE_REVOCATION));

        CBORObject validity = CBORObject.NewOrderedMap();
        validity.Add(CBORObject.FromObject("1"),
                CBORObject.FromObjectAndTag(validFrom.toString(), 0));
        validity.Add(CBORObject.FromObject("2"),
                CBORObject.FromObjectAndTag(validFrom.toString(), 0));
        validity.Add(CBORObject.FromObject("3"),
                CBORObject.FromObjectAndTag(validUntil.toString(), 0));
        mso.Add(CBORObject.FromObject("6"), validity);

        mso.Add(CBORObject.FromObject("7"), CBORObject.FromObject(false));
        return mso;
    }

    /**
     * Legacy convenience: rebuild revocation doc on the *current* document.
     * Equivalent to {@code rebuildRevocationDocument(ctx, getCurrentDocumentId(ctx), entries, validDays)}.
     */
    private static String rebuildRevocationDocument(Context context,
                                                     List<ElementEntry> accessEntries,
                                                     int validDays)
    {
        return rebuildRevocationDocument(context, getCurrentDocumentId(context),
                accessEntries, validDays);
    }

    /**
     * Rebuild the paired Revocation Document for the named stored document
     * so it has one revocation entry per Access element. Uses a persistent
     * revocation-issuer keypair (separate from the access-doc issuer
     * keypair, but stable across edits *for this docId*).
     */
    private static String rebuildRevocationDocument(Context context,
                                                     String docId,
                                                     List<ElementEntry> accessEntries,
                                                     int validDays)
    {
        try
        {
            if (docId == null) return null;
            // Load or generate the revocation issuer keypair scoped to this doc.
            KeyPair revocKP = loadIssuerKeypair(context, docId, true);
            if (revocKP == null)
            {
                revocKP = AliroCryptoProvider.generateEphemeralKeypair();
                if (revocKP == null) return null;
            }
            byte[] revocPubBytes = uncompressedPoint((ECPublicKey) revocKP.getPublic());

            // For revocation docs, body is { 0: 1 } version-only per Aliro §7.6
            List<ElementEntry> revocEntries = new ArrayList<>();
            for (ElementEntry e : accessEntries)
            {
                revocEntries.add(new ElementEntry(e.elementId, buildMinimalAccessData()));
            }

            CBORObject itemsArray = CBORObject.NewArray();
            CBORObject digestMap  = CBORObject.NewOrderedMap();
            for (int i = 0; i < revocEntries.size(); i++)
            {
                ElementEntry e = revocEntries.get(i);
                byte[] random = AliroCryptoProvider.generateRandom(16);
                CBORObject item = buildIssuerSignedItem(i, random, e.elementId, e.accessData);
                byte[] itemBytes = item.EncodeToBytes();
                CBORObject taggedItem = CBORObject.FromObjectAndTag(
                        CBORObject.FromObject(itemBytes), 24);
                byte[] digest = sha256(taggedItem.EncodeToBytes());
                itemsArray.Add(taggedItem);
                digestMap.Add(CBORObject.FromObject(i), CBORObject.FromObject(digest));
            }

            Instant now   = Instant.now();
            Instant until = now.plusSeconds((long) validDays * 86400);
            CBORObject mso = buildMultiItemRevocationMSO(digestMap, now, until);

            byte[] msoBytes  = mso.EncodeToBytes();
            byte[] signature = coseSign1(revocKP.getPrivate(), msoBytes);
            if (signature == null) return null;

            CBORObject issuerAuth = buildCoseSign1(revocPubBytes, msoBytes, signature);
            CBORObject nameSpaces = CBORObject.NewOrderedMap();
            nameSpaces.Add(CBORObject.FromObject(NAMESPACE_REVOCATION), itemsArray);

            CBORObject issuerSigned = CBORObject.NewOrderedMap();
            issuerSigned.Add(CBORObject.FromObject("1"), nameSpaces);
            issuerSigned.Add(CBORObject.FromObject("2"), issuerAuth);

            CBORObject document = CBORObject.NewOrderedMap();
            document.Add(CBORObject.FromObject("1"), issuerSigned);
            document.Add(CBORObject.FromObject("5"), CBORObject.FromObject(DOCTYPE_REVOCATION));

            CBORObject docResponse = CBORObject.NewOrderedMap();
            docResponse.Add(CBORObject.FromObject("1"), CBORObject.FromObject("1.0"));
            CBORObject docs = CBORObject.NewArray();
            docs.Add(document);
            docResponse.Add(CBORObject.FromObject("2"), docs);
            docResponse.Add(CBORObject.FromObject("3"), CBORObject.FromObject(0));

            byte[] cborBytes = docResponse.EncodeToBytes();
            String csv     = joinElementIds(revocEntries);

            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
                    .putString(docKey(KEY_REVOC_DOC,             docId), Base64.encodeToString(cborBytes, Base64.DEFAULT))
                    .putString(docKey(KEY_REVOC_ISSUER_PUB_KEY,  docId), Hex.toHexString(revocPubBytes))
                    .putString(docKey(KEY_REVOC_ISSUER_PRIV_KEY, docId), Hex.toHexString(revocKP.getPrivate().getEncoded()))
                    .putString(docKey(KEY_REVOC_ELEMENT_IDS,     docId), csv)
                    .apply();

            Log.d(TAG, "rebuildRevocationDocument: docId=" + docId + " "
                    + revocEntries.size() + " elements, " + cborBytes.length + " bytes");
            return "ok";
        }
        catch (Exception e)
        {
            Log.e(TAG, "rebuildRevocationDocument failed", e);
            return null;
        }
    }

    /**
     * Decode a stored DeviceResponse and extract every IssuerSignedItem in the
     * given namespace as ElementEntry records, preserving document order.
     */
    private static List<ElementEntry> extractAllElements(byte[] docBytes, String namespaceName)
    {
        List<ElementEntry> out = new ArrayList<>();
        try
        {
            CBORObject docResponse = CBORObject.DecodeFromBytes(docBytes);
            CBORObject docs        = docResponse.get(CBORObject.FromObject("2"));
            if (docs == null || docs.size() == 0) return out;
            CBORObject firstDoc = docs.get(0);
            CBORObject iSigned  = firstDoc.get(CBORObject.FromObject("1"));
            CBORObject ns       = iSigned.get(CBORObject.FromObject("1"));
            CBORObject items    = ns.get(CBORObject.FromObject(namespaceName));
            if (items == null) return out;

            for (int i = 0; i < items.size(); i++)
            {
                CBORObject taggedItem = items.get(i);
                byte[] itemBytes;
                if (taggedItem.isTagged() && taggedItem.getMostOuterTag().ToInt32Checked() == 24)
                {
                    itemBytes = taggedItem.GetByteString();
                }
                else if (taggedItem.getType() == com.upokecenter.cbor.CBORType.ByteString)
                {
                    itemBytes = taggedItem.GetByteString();
                }
                else
                {
                    continue;
                }
                CBORObject item = CBORObject.DecodeFromBytes(itemBytes);
                CBORObject eid  = item.get(CBORObject.FromObject("3"));
                CBORObject val  = item.get(CBORObject.FromObject("4"));
                if (eid != null && val != null)
                {
                    out.add(new ElementEntry(eid.AsString(), val));
                }
            }
        }
        catch (Exception e)
        {
            Log.w(TAG, "extractAllElements failed: " + e.getMessage());
        }
        return out;
    }

    /**
     * Extract the credential public key (uncompressed 65 bytes) from a stored
     * Access Document's MSO deviceKeyInfo (key "4" → "1" → COSE_Key).
     */
    private static byte[] extractCredentialPublicKey(byte[] docBytes)
    {
        try
        {
            CBORObject docResponse = CBORObject.DecodeFromBytes(docBytes);
            CBORObject docs        = docResponse.get(CBORObject.FromObject("2"));
            CBORObject firstDoc    = docs.get(0);
            CBORObject iSigned     = firstDoc.get(CBORObject.FromObject("1"));
            CBORObject iAuth       = iSigned.get(CBORObject.FromObject("2"));
            byte[] payloadBytes    = iAuth.get(2).GetByteString();
            CBORObject tagged      = CBORObject.DecodeFromBytes(payloadBytes);
            byte[] msoBytes        = tagged.GetByteString();
            CBORObject mso         = CBORObject.DecodeFromBytes(msoBytes);
            CBORObject deviceKeyInfo = mso.get(CBORObject.FromObject("4"));
            if (deviceKeyInfo == null) return null;
            CBORObject coseKey     = deviceKeyInfo.get(CBORObject.FromObject("1"));
            if (coseKey == null) return null;
            byte[] x = coseKey.get(CBORObject.FromObject(-2)).GetByteString();
            byte[] y = coseKey.get(CBORObject.FromObject(-3)).GetByteString();
            byte[] out = new byte[65];
            out[0] = 0x04;
            // x and y may be < 32 bytes (leading zero stripped) — left-pad to 32
            System.arraycopy(x, 0, out, 1 + (32 - x.length), x.length);
            System.arraycopy(y, 0, out, 33 + (32 - y.length), y.length);
            return out;
        }
        catch (Exception e)
        {
            Log.w(TAG, "extractCredentialPublicKey failed: " + e.getMessage());
            return null;
        }
    }


    // =========================================================================
    // AccessData builders
    // =========================================================================

    // -------------------------------------------------------------------------
    // v11: per-document content configurability (§7.3 / Table 7-5)
    //
    // SchedulePreset selects one of five canonical AccessRules+Schedules
    // shapes, all spec-conformant. AccessDocConfig bundles the badge metadata
    // (name, Employee/Badge ID, preset) so each stored Access Document can
    // carry visibly distinct content. buildAccessDataFromConfig() emits the
    // CBOR map; the rest of the pipeline (digests, MSO, COSE_Sign1) is
    // unchanged from the single-shape path.
    // -------------------------------------------------------------------------

    /**
     * Schedule preset selecting which AccessRules + Schedules shape goes into
     * the AccessData CBOR. All values produce spec-conformant output per
     * Aliro 1.0 §7.3 / Table 7-5.
     *
     * UI labels (kept in sync with fragment_credential_aliro_config.xml):
     *   ALWAYS_ALLOW_24X7    — "Always Allow (24x7)"
     *   WEEKDAY_AND_WEEKEND  — "Weekday + Weekend (legacy sample)"
     *   WEEKDAY_EXTENDED     — "Weekday Extended (06:00-22:00)"
     *   WEEKEND_24H          — "Weekend 24h (Secure only)"
     *   NIGHT_SHIFT          — "Night Shift (Mon-Fri 22:00-06:00)"
     */
    public enum SchedulePreset
    {
        ALWAYS_ALLOW_24X7,
        WEEKDAY_AND_WEEKEND,
        WEEKDAY_EXTENDED,
        WEEKEND_24H,
        NIGHT_SHIFT
    }

    /**
     * Per-document content configuration. The {@code name} field is purely a
     * label for the credential UI; only {@code employeeId} and {@code preset}
     * affect the on-wire CBOR.
     */
    public static class AccessDocConfig
    {
        public final String name;
        public final String employeeId;
        public final SchedulePreset preset;

        public AccessDocConfig(String name, String employeeId, SchedulePreset preset)
        {
            this.name       = name;
            this.employeeId = employeeId;
            this.preset     = preset;
        }
    }

    // ---- Day-of-week bit constants (§7.3.4) ---------------------------------
    // bit 0 = Mon, bit 1 = Tue, ..., bit 6 = Sun
    private static final int DAY_MON_FRI = 0x1F;
    private static final int DAY_SAT_SUN = 0x60;
    private static final int DAY_ALL     = 0x7F;

    // ---- Capability bit constants (§7.3.3 Table 7-7) ------------------------
    private static final int CAP_SECURE             = 0x01;
    private static final int CAP_UNSECURE           = 0x02;
    private static final int CAP_MOMENTARY_UNSECURE = 0x08;
    private static final int CAP_FULL = CAP_SECURE | CAP_UNSECURE | CAP_MOMENTARY_UNSECURE;

    // ---- Preset validity windows -------------------------------------------
    // The legacy buildRealisticAccessData uses LEGACY_END_PERIOD as its
    // schedule endPeriod. WEEKDAY_AND_WEEKEND below shares that exact value
    // so its CBOR is byte-identical to documents already in the field for
    // employeeId="ELATEC001". All OTHER presets use FAR_FUTURE_END_PERIOD,
    // which is far enough in the future that the overall schedule window
    // stays in-range for the foreseeable life of this demo without hitting
    // the §7.3.4 [start, endPeriod) expiration cliff. Without this split
    // every preset would expire on 2026-04-30 00:00 UTC and refuse access
    // for any subsequent test, even when the time-of-day window was active.
    private static final long LEGACY_END_PERIOD     = 1777507200L; // 2026-04-30 00:00 UTC
    private static final long FAR_FUTURE_END_PERIOD = 1893456000L; // 2030-01-01 00:00 UTC

    /**
     * Build the AccessData CBOR map for the given configuration. The output
     * conforms to Aliro 1.0 §7.3 / Table 7-5: keys 0/1/2/3 = version, id,
     * AccessRules, Schedules. Capability bitmasks use only the spec-defined
     * bits 0x01/0x02/0x08; recurrenceRule pattern is always 2 (Weekly);
     * dayMask uses only bits 0..6 (within 0x7F).
     *
     * <p>Wire-format note: for byte-level back-compat with previously stored
     * Access Documents, {@link SchedulePreset#WEEKDAY_AND_WEEKEND} produces
     * the same bytes as the legacy {@link #buildRealisticAccessData()} when
     * called with employeeId="ELATEC001".
     *
     * @param config metadata + preset selection; must be non-null with non-null fields
     * @return CBOR map ready to be wrapped into an IssuerSignedItem
     */
    public static CBORObject buildAccessDataFromConfig(AccessDocConfig config)
    {
        if (config == null) throw new IllegalArgumentException("config is null");
        if (config.employeeId == null) throw new IllegalArgumentException("employeeId is null");
        if (config.preset == null) throw new IllegalArgumentException("preset is null");

        // Encode employeeId as UTF-8 bstr for AccessData.id (key 1, Table 7-5).
        // The test suite uses GetByteString() to recover it, so the value MUST
        // be a CBOR byte string — not a text string.
        byte[] idBytes = config.employeeId.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        CBORObject accessRules;
        CBORObject schedules;

        switch (config.preset)
        {
            case ALWAYS_ALLOW_24X7:
            {
                // Single rule, single schedule that covers every day for 24 h.
                CBORObject rule = newAccessRule(CAP_FULL, 0x01);
                accessRules = newArray(rule);

                // 24-hour window starting at midnight UTC, recurring all 7 days.
                CBORObject schedule = newSchedule(
                        /* startPeriod = */ 1745971200L, // 2025-04-30 00:00 UTC
                        /* endPeriod   = */ FAR_FUTURE_END_PERIOD,
                        /* duration    = */ 86400,
                        /* dayMask     = */ DAY_ALL,
                        /* flagsUtc    = */ true);
                schedules = newArray(schedule);
                break;
            }
            case WEEKDAY_AND_WEEKEND:
            {
                // Legacy two-rule / two-schedule shape, byte-identical to
                // buildRealisticAccessData() (when employeeId="ELATEC001").
                CBORObject rule0 = newAccessRule(CAP_FULL,    0x01); // weekday: full caps
                CBORObject rule1 = newAccessRule(CAP_SECURE,  0x02); // weekend: secure only
                accessRules = newArray(rule0, rule1);

                CBORObject sched0 = newSchedule(
                        1745996400L,            // 2025-04-30 07:00 UTC
                        LEGACY_END_PERIOD,
                        12 * 3600,
                        DAY_MON_FRI,
                        true);
                CBORObject sched1 = newSchedule(
                        1746003600L,            // 2025-04-30 09:00 UTC
                        LEGACY_END_PERIOD,
                        8 * 3600,
                        DAY_SAT_SUN,
                        true);
                schedules = newArray(sched0, sched1);
                break;
            }
            case WEEKDAY_EXTENDED:
            {
                // Mon-Fri 06:00-22:00 UTC, full capabilities.
                CBORObject rule = newAccessRule(CAP_FULL, 0x01);
                accessRules = newArray(rule);

                CBORObject schedule = newSchedule(
                        1745992800L,            // 2025-04-30 06:00 UTC (TOD = 21600)
                        FAR_FUTURE_END_PERIOD,
                        16 * 3600,              // 06:00 → 22:00
                        DAY_MON_FRI,
                        true);
                schedules = newArray(schedule);
                break;
            }
            case WEEKEND_24H:
            {
                // Sat+Sun for the full 24 h, Secure capability only.
                CBORObject rule = newAccessRule(CAP_SECURE, 0x01);
                accessRules = newArray(rule);

                CBORObject schedule = newSchedule(
                        1745971200L,            // 2025-04-30 00:00 UTC
                        FAR_FUTURE_END_PERIOD,
                        86400,
                        DAY_SAT_SUN,
                        true);
                schedules = newArray(schedule);
                break;
            }
            case NIGHT_SHIFT:
            {
                // Mon-Fri 22:00 → 06:00 (cross-midnight). Per Aliro §7.3.4 the
                // recurrenceRule's dayMask names the START day; the duration
                // carries the window across midnight when needed. Test
                // testVerifierNightShiftCrossMidnight asserts:
                //   duration = 8h, dayMask = 0x1F, pattern = 2,
                //   startPeriod % 86400 == 79200 (TOD anchor 22:00 UTC)
                CBORObject rule = newAccessRule(CAP_FULL, 0x01);
                accessRules = newArray(rule);

                CBORObject schedule = newSchedule(
                        1746050400L,            // 2025-04-30 22:00 UTC (TOD = 79200)
                        FAR_FUTURE_END_PERIOD,
                        8 * 3600,
                        DAY_MON_FRI,
                        true);
                schedules = newArray(schedule);
                break;
            }
            default:
                throw new AssertionError("Unhandled SchedulePreset: " + config.preset);
        }

        CBORObject accessData = CBORObject.NewOrderedMap();
        accessData.Add(CBORObject.FromObject(0), CBORObject.FromObject(1));        // version
        accessData.Add(CBORObject.FromObject(1), CBORObject.FromObject(idBytes));  // id (bstr)
        accessData.Add(CBORObject.FromObject(2), accessRules);
        accessData.Add(CBORObject.FromObject(3), schedules);
        return accessData;
    }

    /**
     * Inspect a stored DeviceResponse and report whether the first contained
     * Access Document's Validity window covers "now" (per §8.4.2 SHOULD-check).
     *
     * Returns false when the document is expired, not-yet-valid, malformed, or
     * cannot be parsed. Never throws — designed to be a safe pre-flight check.
     *
     * Navigation: deviceResponse → "2"[0] → "1" → "2" (IssuerAuth COSE_Sign1)
     * → element [2] (payload bstr) → decode tag-24 → MSO → "6" → check "2"
     * (validFrom) and "3" (validUntil) parsed as RFC 3339 dates.
     */
    public static boolean isValidityCurrent(byte[] deviceResponseBytes)
    {
        if (deviceResponseBytes == null || deviceResponseBytes.length == 0) return false;
        try
        {
            CBORObject dr = CBORObject.DecodeFromBytes(deviceResponseBytes);
            CBORObject docs = dr.get(CBORObject.FromObject("2"));
            if (docs == null || docs.size() == 0) return false;

            CBORObject doc       = docs.get(0);
            CBORObject iSigned   = doc.get(CBORObject.FromObject("1"));
            if (iSigned == null) return false;
            CBORObject iAuth     = iSigned.get(CBORObject.FromObject("2"));
            if (iAuth == null || iAuth.size() < 4) return false;

            // COSE_Sign1[2] = payload bstr. The bstr's contents are #6.24(bstr(MSO)).
            CBORObject payloadBs = iAuth.get(2);
            byte[] payloadBytes = payloadBs.GetByteString();
            CBORObject tagged = CBORObject.DecodeFromBytes(payloadBytes);
            byte[] msoBytes = tagged.GetByteString();
            CBORObject mso = CBORObject.DecodeFromBytes(msoBytes);

            CBORObject validity = mso.get(CBORObject.FromObject("6"));
            if (validity == null) return false;

            CBORObject fromObj  = validity.get(CBORObject.FromObject("2"));
            CBORObject untilObj = validity.get(CBORObject.FromObject("3"));
            if (fromObj == null || untilObj == null) return false;

            Instant validFrom  = Instant.parse(fromObj.AsString());
            Instant validUntil = Instant.parse(untilObj.AsString());
            Instant now = Instant.now();
            return !now.isBefore(validFrom) && !now.isAfter(validUntil);
        }
        catch (Exception e)
        {
            Log.w(TAG, "isValidityCurrent: parse failed: " + e.getMessage());
            return false;
        }
    }

    // ---- AccessData CBOR builder helpers ------------------------------------

    private static CBORObject newAccessRule(int capabilities, int allowScheduleIds)
    {
        CBORObject rule = CBORObject.NewOrderedMap();
        rule.Add(CBORObject.FromObject(0), CBORObject.FromObject(capabilities));
        rule.Add(CBORObject.FromObject(1), CBORObject.FromObject(allowScheduleIds));
        return rule;
    }

    private static CBORObject newSchedule(long startPeriod, long endPeriod,
                                           int durationSeconds, int dayMask,
                                           boolean flagsUtc)
    {
        // recurrenceRule = [durationSeconds, dayMask, pattern, interval, ordinal]
        // pattern = 2 (Weekly), interval = 1 (every week), ordinal = 0 (unused).
        CBORObject recRule = CBORObject.NewArray();
        recRule.Add(CBORObject.FromObject(durationSeconds));
        recRule.Add(CBORObject.FromObject(dayMask));
        recRule.Add(CBORObject.FromObject(2));
        recRule.Add(CBORObject.FromObject(1));
        recRule.Add(CBORObject.FromObject(0));

        CBORObject schedule = CBORObject.NewOrderedMap();
        schedule.Add(CBORObject.FromObject(0), CBORObject.FromObject(startPeriod));
        schedule.Add(CBORObject.FromObject(1), CBORObject.FromObject(endPeriod));
        schedule.Add(CBORObject.FromObject(2), recRule);
        schedule.Add(CBORObject.FromObject(3), CBORObject.FromObject(flagsUtc ? 0x01 : 0x00));
        return schedule;
    }

    private static CBORObject newArray(CBORObject... items)
    {
        CBORObject arr = CBORObject.NewArray();
        for (CBORObject item : items) arr.Add(item);
        return arr;
    }

    // -------------------------------------------------------------------------

    /**
     * Build minimal AccessData: { 0: 1 } — version only.
     * Used by generateTestDocument() and generateRevocationDocument().
     */
    private static CBORObject buildMinimalAccessData()
    {
        CBORObject accessData = CBORObject.NewOrderedMap();
        accessData.Add(CBORObject.FromObject(0), CBORObject.FromObject(1)); // version=1
        return accessData;
    }

    /**
     * Build a realistic employee-badge AccessData per Aliro 1.0 §7.3.
     *
     * Structure:
     * {
     *   0: 1,                           // version
     *   1: h'454C41544543303031',       // id = "ELATEC001"
     *   2: [                            // AccessRules
     *     { 0: 0x0B, 1: 0x01 },        // Rule 0: Secure+Unsecure+Momentary on schedule 0
     *     { 0: 0x01, 1: 0x02 }         // Rule 1: Secure only on schedule 1
     *   ],
     *   3: [                            // Schedules
     *     {                             // Schedule 0: Mon-Fri 07:00-19:00 UTC
     *       0: 1745996400,              // startPeriod: 2025-04-30 07:00:00 UTC (TOD=07:00)
     *       1: 1777507200,              // endPeriod:   2026-04-30 00:00:00 UTC
     *       2: [43200, 0x1F, 2, 1, 0], // 12h, Mon-Fri, Weekly, every 1 week
     *       3: 0x01                     // flags: Time_in_UTC
     *     },
     *     {                             // Schedule 1: Sat-Sun 09:00-17:00 UTC
     *       0: 1746003600,              // startPeriod: 2025-04-30 09:00:00 UTC (TOD=09:00)
     *       1: 1777507200,
     *       2: [28800, 0x60, 2, 1, 0], // 8h, Sat+Sun, Weekly, every 1 week
     *       3: 0x01
     *     }
     *   ]
     * }
     *
     * Capability bitmask (§7.3.3 Table 7-7):
     *   bit 0 = Secure (0x01)
     *   bit 1 = Unsecure (0x02)
     *   bit 3 = Momentary_Unsecure (0x08)
     *   => 0x01 | 0x02 | 0x08 = 0x0B for rule 0 (weekday full access)
     *   => 0x01 for rule 1 (weekend secure only)
     *
     * Day-of-week mask (§7.3.4):
     *   bit 0=Mon, 1=Tue, 2=Wed, 3=Thu, 4=Fri, 5=Sat, 6=Sun
     *   0x1F = Mon-Fri; 0x60 = Sat+Sun
     *
     * recurrenceRule pattern 2 = Weekly (§7.3.4 Table 7-9)
     */
    private static CBORObject buildRealisticAccessData()
    {
        // ---- Employee ID ----
        // "ELATEC001" as UTF-8 bytes: 45 4C 41 54 45 43 30 30 31
        byte[] employeeId = new byte[] {
            0x45, 0x4C, 0x41, 0x54, 0x45, 0x43, 0x30, 0x30, 0x31
        };

        // ---- Access Rule 0: Weekday business hours ----
        // capabilities: Secure(bit0) + Unsecure(bit1) + Momentary_Unsecure(bit3) = 0x0B
        // allowScheduleIds: schedule 0 (bit 0) = 0x01
        CBORObject rule0 = CBORObject.NewOrderedMap();
        rule0.Add(CBORObject.FromObject(0), CBORObject.FromObject(0x0B)); // capabilities
        rule0.Add(CBORObject.FromObject(1), CBORObject.FromObject(0x01)); // schedule bitmask

        // ---- Access Rule 1: Weekend emergency ----
        // capabilities: Secure only (bit 0) = 0x01
        // allowScheduleIds: schedule 1 (bit 1) = 0x02
        CBORObject rule1 = CBORObject.NewOrderedMap();
        rule1.Add(CBORObject.FromObject(0), CBORObject.FromObject(0x01)); // capabilities
        rule1.Add(CBORObject.FromObject(1), CBORObject.FromObject(0x02)); // schedule bitmask

        CBORObject accessRules = CBORObject.NewArray();
        accessRules.Add(rule0);
        accessRules.Add(rule1);

        // ---- Schedule 0: Weekday 07:00-19:00 UTC (Mon-Fri, recurring weekly) ----
        // startPeriod: 2025-04-30 07:00:00 UTC = 1745996400
        //   The time-of-day component of startPeriod (07:00 UTC = 25200s past midnight)
        //   defines when the recurring daily window opens. Combined with duration=43200s
        //   (12 hours), the window is 07:00-19:00 UTC on each applicable day.
        // endPeriod:   2026-04-30 00:00:00 UTC = 1777507200
        // durationSeconds: 12 * 3600 = 43200
        // dayMask: Mon-Fri = bits 0-4 = 0x1F
        // pattern: 2 = Weekly
        // interval: 1 (every week)
        // ordinal: 0 (not used for weekly)
        CBORObject recRule0 = CBORObject.NewArray();
        recRule0.Add(CBORObject.FromObject(43200)); // durationSeconds (12 h)
        recRule0.Add(CBORObject.FromObject(0x1F));  // dayMask: Mon-Fri
        recRule0.Add(CBORObject.FromObject(2));     // pattern: Weekly
        recRule0.Add(CBORObject.FromObject(1));     // interval: every 1 week
        recRule0.Add(CBORObject.FromObject(0));     // ordinal: unused

        CBORObject schedule0 = CBORObject.NewOrderedMap();
        schedule0.Add(CBORObject.FromObject(0), CBORObject.FromObject(1745996400L)); // startPeriod: 2025-04-30 07:00 UTC
        schedule0.Add(CBORObject.FromObject(1), CBORObject.FromObject(1777507200L)); // endPeriod:   2026-04-30 00:00 UTC
        schedule0.Add(CBORObject.FromObject(2), recRule0);                            // recurrenceRule
        schedule0.Add(CBORObject.FromObject(3), CBORObject.FromObject(0x01));         // flags: UTC

        // ---- Schedule 1: Weekend 09:00-17:00 UTC (Sat-Sun, recurring weekly) ----
        // startPeriod: 2025-04-30 09:00:00 UTC = 1746003600
        //   TOD = 09:00 UTC = 32400s. Window = [09:00, 09:00+28800) = [09:00, 17:00) UTC.
        // durationSeconds: 8 * 3600 = 28800
        // dayMask: Sat+Sun = bits 5,6 = 0x60
        CBORObject recRule1 = CBORObject.NewArray();
        recRule1.Add(CBORObject.FromObject(28800)); // durationSeconds (8 h)
        recRule1.Add(CBORObject.FromObject(0x60));  // dayMask: Sat+Sun
        recRule1.Add(CBORObject.FromObject(2));     // pattern: Weekly
        recRule1.Add(CBORObject.FromObject(1));     // interval: every 1 week
        recRule1.Add(CBORObject.FromObject(0));     // ordinal: unused

        CBORObject schedule1 = CBORObject.NewOrderedMap();
        schedule1.Add(CBORObject.FromObject(0), CBORObject.FromObject(1746003600L)); // startPeriod: 2025-04-30 09:00 UTC
        schedule1.Add(CBORObject.FromObject(1), CBORObject.FromObject(1777507200L)); // endPeriod:   2026-04-30 00:00 UTC
        schedule1.Add(CBORObject.FromObject(2), recRule1);                            // recurrenceRule
        schedule1.Add(CBORObject.FromObject(3), CBORObject.FromObject(0x01));         // flags: UTC

        CBORObject schedules = CBORObject.NewArray();
        schedules.Add(schedule0);
        schedules.Add(schedule1);

        // ---- Assemble AccessData ----
        CBORObject accessData = CBORObject.NewOrderedMap();
        accessData.Add(CBORObject.FromObject(0), CBORObject.FromObject(1));                    // version
        accessData.Add(CBORObject.FromObject(1), CBORObject.FromObject(employeeId));           // id
        accessData.Add(CBORObject.FromObject(2), accessRules);                                 // AccessRules
        accessData.Add(CBORObject.FromObject(3), schedules);                                   // Schedules

        return accessData;
    }

    // =========================================================================
    // CBOR building helpers
    // =========================================================================

    /**
     * Build IssuerSignedItem per Table 7-2:
     *   { "1": digestID, "2": random(bstr), "3": elementIdentifier, "4": elementValue }
     */
    private static CBORObject buildIssuerSignedItem(int digestId, byte[] random,
                                                     String elementIdentifier,
                                                     CBORObject elementValue)
    {
        // Per Aliro Table 7-2, IssuerSignedItem uses abbreviated keys (SHALL).
        // Deterministic CBOR order: "1" < "2" < "3" < "4"
        CBORObject item = CBORObject.NewOrderedMap();
        item.Add(CBORObject.FromObject("1"), CBORObject.FromObject(digestId));          // digestID
        item.Add(CBORObject.FromObject("2"), CBORObject.FromObject(random));            // random
        item.Add(CBORObject.FromObject("3"), CBORObject.FromObject(elementIdentifier)); // elementIdentifier
        item.Add(CBORObject.FromObject("4"), elementValue);                             // elementValue
        return item;
    }

    /**
     * Build MobileSecurityObject per §7.2 + Table 7-1.
     * Keys are remapped integers-as-text-strings per Table 7-1.
     * Includes deviceKeyInfo at key "4".
     */
    private static CBORObject buildMSO(byte[] credPubKeyBytes,
                                        String elementIdentifier,
                                        int digestId, byte[] digest,
                                        Instant validFrom, Instant validUntil)
    {
        // MSO (MobileSecurityObject) per Aliro §7.2.2 + Table 7-1.
        // Keys SHALL be replaced with abbreviated keys per Table 7-1.
        // Deterministic CBOR order (RFC 8949 §4.2.1): "1" < "2" < "3" < "4" < "5" < "6"
        CBORObject mso = CBORObject.NewOrderedMap();

        // "1" = version
        mso.Add(CBORObject.FromObject("1"), CBORObject.FromObject("1.0"));

        // "2" = digestAlgorithm
        mso.Add(CBORObject.FromObject("2"), CBORObject.FromObject("SHA-256"));

        // "3" = valueDigests
        CBORObject digestMap = CBORObject.NewOrderedMap();
        digestMap.Add(CBORObject.FromObject(digestId), CBORObject.FromObject(digest));
        CBORObject valueDigests = CBORObject.NewOrderedMap();
        valueDigests.Add(CBORObject.FromObject(NAMESPACE_ACCESS), digestMap);
        mso.Add(CBORObject.FromObject("3"), valueDigests);

        // "4" = deviceKeyInfo { "1" = deviceKey }
        CBORObject coseKey = buildCoseEcKey(credPubKeyBytes);
        CBORObject deviceKeyInfo = CBORObject.NewOrderedMap();
        deviceKeyInfo.Add(CBORObject.FromObject("1"), coseKey);
        mso.Add(CBORObject.FromObject("4"), deviceKeyInfo);

        // "5" = docType
        mso.Add(CBORObject.FromObject("5"), CBORObject.FromObject(DOCTYPE_ACCESS));

        // "6" = validityInfo { "1" = signed, "2" = validFrom, "3" = validUntil }
        // Per ISO 18013-5, tdate = #6.0(tstr) — CBOR tag 0 wrapping RFC 3339 date string.
        CBORObject validity = CBORObject.NewOrderedMap();
        validity.Add(CBORObject.FromObject("1"),
                CBORObject.FromObjectAndTag(validFrom.toString(), 0));
        validity.Add(CBORObject.FromObject("2"),
                CBORObject.FromObjectAndTag(validFrom.toString(), 0));
        validity.Add(CBORObject.FromObject("3"),
                CBORObject.FromObjectAndTag(validUntil.toString(), 0));
        mso.Add(CBORObject.FromObject("6"), validity);

        // "7" = timeVerificationRequired (boolean)
        // Per Aliro §7.2.2: "SHALL be present in the MobileSecurityObject"
        // Per §7.2.4: false means Reader MAY skip time validation.
        mso.Add(CBORObject.FromObject("7"), CBORObject.FromObject(false));

        return mso;
    }

    /**
     * Build MobileSecurityObject for Revocation Document per §7.6 + Table 7-1.
     * Same as buildMSO() but WITHOUT key "4" (deviceKeyInfo) per Aliro §7.6.
     * Keys: "1" (version), "2" (digestAlgorithm), "3" (valueDigests),
     *       "5" (docType = "aliro-r"), "6" (validityInfo), "7" (timeVerificationRequired)
     */
    private static CBORObject buildRevocationMSO(String elementIdentifier,
                                                   int digestId, byte[] digest,
                                                   Instant validFrom, Instant validUntil)
    {
        CBORObject mso = CBORObject.NewOrderedMap();

        // "1" = version
        mso.Add(CBORObject.FromObject("1"), CBORObject.FromObject("1.0"));

        // "2" = digestAlgorithm
        mso.Add(CBORObject.FromObject("2"), CBORObject.FromObject("SHA-256"));

        // "3" = valueDigests (uses "aliro-r" namespace)
        CBORObject digestMap = CBORObject.NewOrderedMap();
        digestMap.Add(CBORObject.FromObject(digestId), CBORObject.FromObject(digest));
        CBORObject valueDigests = CBORObject.NewOrderedMap();
        valueDigests.Add(CBORObject.FromObject(NAMESPACE_REVOCATION), digestMap);
        mso.Add(CBORObject.FromObject("3"), valueDigests);

        // Key "4" (deviceKeyInfo) is intentionally OMITTED per Aliro §7.6

        // "5" = docType = "aliro-r"
        mso.Add(CBORObject.FromObject("5"), CBORObject.FromObject(DOCTYPE_REVOCATION));

        // "6" = validityInfo { "1" = signed, "2" = validFrom, "3" = validUntil }
        CBORObject validity = CBORObject.NewOrderedMap();
        validity.Add(CBORObject.FromObject("1"),
                CBORObject.FromObjectAndTag(validFrom.toString(), 0));
        validity.Add(CBORObject.FromObject("2"),
                CBORObject.FromObjectAndTag(validFrom.toString(), 0));
        validity.Add(CBORObject.FromObject("3"),
                CBORObject.FromObjectAndTag(validUntil.toString(), 0));
        mso.Add(CBORObject.FromObject("6"), validity);

        // "7" = timeVerificationRequired (boolean)
        mso.Add(CBORObject.FromObject("7"), CBORObject.FromObject(false));

        return mso;
    }

    /**
     * Build a COSE_Key for a P-256 public key per RFC 8152.
     * kty=2 (EC2), crv=1 (P-256), x=..., y=...
     */
    private static CBORObject buildCoseEcKey(byte[] uncompressed65)
    {
        byte[] x = Arrays.copyOfRange(uncompressed65, 1, 33);
        byte[] y = Arrays.copyOfRange(uncompressed65, 33, 65);
        CBORObject key = CBORObject.NewOrderedMap();
        key.Add(CBORObject.FromObject(1), CBORObject.FromObject(2));  // kty = EC2
        key.Add(CBORObject.FromObject(-1), CBORObject.FromObject(1)); // crv = P-256
        key.Add(CBORObject.FromObject(-2), CBORObject.FromObject(x)); // x
        key.Add(CBORObject.FromObject(-3), CBORObject.FromObject(y)); // y
        return key;
    }

    /**
     * Build COSE_Sign1 array: [protected_header, unprotected_header, payload, signature]
     * Protected header: { 1: -7 }  (alg = ES256)
     * Unprotected header: { 4: kid }  where kid = first 8 bytes of SHA-256("key-identifier" || 0x04 || issuerPubKey)
     */
    private static CBORObject buildCoseSign1(byte[] issuerPubBytes,
                                              byte[] msoBytes,
                                              byte[] signature)
    {
        // Protected header: alg = -7 (ES256)
        CBORObject protectedHeader = CBORObject.NewOrderedMap();
        protectedHeader.Add(CBORObject.FromObject(1), CBORObject.FromObject(-7));
        byte[] protectedBytes = protectedHeader.EncodeToBytes();

        // Unprotected header: kid per §7.2.1
        byte[] kid = computeKid(issuerPubBytes);
        CBORObject unprotectedHeader = CBORObject.NewOrderedMap();
        if (kid != null)
        {
            unprotectedHeader.Add(CBORObject.FromObject(4), CBORObject.FromObject(kid));
        }

        // Per ISO 18013-5 §9.1.2.4, the payload is MobileSecurityObjectBytes =
        // #6.24(bstr .cbor MobileSecurityObject) — the MSO bytes wrapped in CBOR tag 24.
        // The harness decodes the payload and expects CBORTag(24, bstr).
        CBORObject taggedPayload = CBORObject.FromObjectAndTag(
                CBORObject.FromObject(msoBytes), 24);
        byte[] payloadBytes = taggedPayload.EncodeToBytes();

        CBORObject coseSign1 = CBORObject.NewArray();
        coseSign1.Add(CBORObject.FromObject(protectedBytes));
        coseSign1.Add(unprotectedHeader);
        coseSign1.Add(CBORObject.FromObject(payloadBytes)); // payload = #6.24(bstr(MSO))
        coseSign1.Add(CBORObject.FromObject(signature));

        // NOTE: Do NOT wrap in CBOR tag 18. The Aliro test harness Python code
        // accesses IssuerAuth elements via subscript (issuerAuth[0], etc.) and
        // crashes with "'CBORTag' object is not subscriptable" if tag 18 is present.
        // Per ISO 18013-5, COSE_Sign1 tag is optional when type is known from context.
        return coseSign1;
    }

    /**
     * Sign MobileSecurityObject bytes with ECDSA SHA-256 (ES256).
     * COSE_Sign1 Sig_Structure: ["Signature1", protected_header, external_aad, payload]
     * Returns raw 64-byte R||S signature.
     */
    private static byte[] coseSign1(PrivateKey issuerPrivKey, byte[] msoBytes)
    {
        try
        {
            // Build protected header bytes
            CBORObject protectedHeader = CBORObject.NewOrderedMap();
            protectedHeader.Add(CBORObject.FromObject(1), CBORObject.FromObject(-7));
            byte[] protectedBytes = protectedHeader.EncodeToBytes();

            // The payload stored in COSE_Sign1 is #6.24(bstr(MSO)) per ISO 18013-5 §9.1.2.4.
            // The Sig_Structure signs over the payload AS STORED, i.e. the tagged bytes.
            CBORObject taggedPayload = CBORObject.FromObjectAndTag(
                    CBORObject.FromObject(msoBytes), 24);
            byte[] payloadBytes = taggedPayload.EncodeToBytes();

            // Sig_Structure = ["Signature1", bstr(protected), bstr(external_aad=""), bstr(payload)]
            CBORObject sigStructure = CBORObject.NewArray();
            sigStructure.Add(CBORObject.FromObject("Signature1"));
            sigStructure.Add(CBORObject.FromObject(protectedBytes));
            sigStructure.Add(CBORObject.FromObject(new byte[0])); // empty external_aad
            sigStructure.Add(CBORObject.FromObject(payloadBytes));

            byte[] toBeSigned = sigStructure.EncodeToBytes();

            // Sign with ECDSA SHA-256 — no provider specified, Android resolves correctly
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(issuerPrivKey);
            sig.update(toBeSigned);
            byte[] derSig = sig.sign();

            // Convert DER to raw 64-byte R||S
            return derToRaw64(derSig);
        }
        catch (Exception e)
        {
            Log.e(TAG, "coseSign1 failed", e);
            return null;
        }
    }

    // =========================================================================
    // Extraction helpers (for import validation + summary)
    // =========================================================================

    private static String extractElementId(CBORObject doc)
    {
        try
        {
            // doc["2"]["1"]["aliro-a"][0] → IssuerSignedItem → ["3"] = elementIdentifier
            CBORObject docs      = doc.get(CBORObject.FromObject("2"));
            if (docs == null || docs.size() == 0) return null;
            CBORObject firstDoc  = docs.get(0);
            CBORObject iSigned   = firstDoc.get(CBORObject.FromObject("1"));
            CBORObject ns        = iSigned.get(CBORObject.FromObject("1"));
            CBORObject items     = ns.get(CBORObject.FromObject(NAMESPACE_ACCESS));
            if (items == null || items.size() == 0) return null;
            byte[] itemBytes     = items.get(0).GetByteString();
            CBORObject item      = CBORObject.DecodeFromBytes(itemBytes);
            CBORObject eid       = item.get(CBORObject.FromObject("3"));
            return eid != null ? eid.AsString() : null;
        }
        catch (Exception e) { return null; }
    }

    /**
     * Extract every element identifier from an Access Document
     * (DeviceResponse CBOR), in the order they appear in the
     * nameSpaces[aliro-a] array.
     *
     * <p>Unlike {@link #extractElementId(CBORObject)}, which returns only
     * the first element identifier, this helper walks every
     * IssuerSignedItem in the aliro-a namespace and returns the full
     * list. It is used by {@link #importDocument(Context, String, String)}
     * to populate {@code KEY_ELEMENT_IDS} so the multi-element matching
     * engine in {@code Aliro_HostApduService.buildDeviceResponse} can find
     * every element the reader may request, not just the first.
     *
     * <p>Per Aliro 1.0 §7.3, all elements in a document share one
     * IssuerAuth. Per §8.4.2, the credential SHOULD return every
     * requested-and-present element. Both rules are honored when this
     * helper's full list is persisted in {@code KEY_ELEMENT_IDS}.
     *
     * @return Comma-separated element identifiers, or empty string if
     *         the document has none / cannot be parsed.
     */
    private static String extractAllElementIds(CBORObject doc)
    {
        try
        {
            CBORObject docs = doc.get(CBORObject.FromObject("2"));
            if (docs == null || docs.size() == 0) return "";
            CBORObject firstDoc = docs.get(0);
            CBORObject iSigned  = firstDoc.get(CBORObject.FromObject("1"));
            CBORObject ns       = iSigned.get(CBORObject.FromObject("1"));
            CBORObject items    = ns.get(CBORObject.FromObject(NAMESPACE_ACCESS));
            if (items == null || items.size() == 0) return "";

            StringBuilder csv = new StringBuilder();
            for (int i = 0; i < items.size(); i++)
            {
                byte[] itemBytes = items.get(i).GetByteString();
                CBORObject item  = CBORObject.DecodeFromBytes(itemBytes);
                CBORObject eid   = item.get(CBORObject.FromObject("3"));
                if (eid == null) continue;
                if (csv.length() > 0) csv.append(",");
                csv.append(eid.AsString());
            }
            return csv.toString();
        }
        catch (Exception e) { return ""; }
    }

    private static String extractValidUntil(CBORObject doc)
    {
        try
        {
            CBORObject docs     = doc.get(CBORObject.FromObject("2"));
            if (docs == null || docs.size() == 0) return null;
            CBORObject firstDoc = docs.get(0);
            CBORObject iSigned  = firstDoc.get(CBORObject.FromObject("1"));
            CBORObject iAuth    = iSigned.get(CBORObject.FromObject("2"));
            // IssuerAuth[2] = payload bytes. Decode to get #6.24(bstr(MSO)).
            byte[] payloadBytes = iAuth.get(2).GetByteString();
            CBORObject tagged   = CBORObject.DecodeFromBytes(payloadBytes);
            // Unwrap tag 24 to get raw MSO bytes, then decode MSO
            byte[] msoBytes     = tagged.GetByteString();
            CBORObject mso      = CBORObject.DecodeFromBytes(msoBytes);
            CBORObject validity = mso.get(CBORObject.FromObject("6"));
            CBORObject until    = validity.get(CBORObject.FromObject("3"));
            return until != null ? until.AsString() : null;
        }
        catch (Exception e) { return null; }
    }

    // =========================================================================
    // Crypto helpers
    // =========================================================================

    private static byte[] sha256(byte[] data) throws Exception
    {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    /**
     * Compute kid per §7.2.1:
     * first 8 bytes of SHA-256("key-identifier" || 0x04 || IssuerKey_PubK.x || IssuerKey_PubK.y)
     */
    private static byte[] computeKid(byte[] issuerPubUncompressed65)
    {
        try
        {
            byte[] prefix = "key-identifier".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] input  = new byte[prefix.length + issuerPubUncompressed65.length];
            System.arraycopy(prefix, 0, input, 0, prefix.length);
            System.arraycopy(issuerPubUncompressed65, 0, input, prefix.length,
                    issuerPubUncompressed65.length);
            byte[] hash = sha256(input);
            return Arrays.copyOfRange(hash, 0, 8);
        }
        catch (Exception e) { return null; }
    }

    /** Convert Java ECPublicKey to 65-byte uncompressed point */
    private static byte[] uncompressedPoint(ECPublicKey pub)
    {
        byte[] x   = toBytes32(pub.getW().getAffineX());
        byte[] y   = toBytes32(pub.getW().getAffineY());
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(x, 0, out, 1,  32);
        System.arraycopy(y, 0, out, 33, 32);
        return out;
    }

    private static byte[] toBytes32(java.math.BigInteger n)
    {
        byte[] raw = n.toByteArray();
        byte[] out = new byte[32];
        if (raw.length <= 32)
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        else
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        return out;
    }

    /**
     * Convert DER ECDSA signature to raw 64-byte R||S.
     */
    private static byte[] derToRaw64(byte[] der)
    {
        int rTotalLen = der[3] & 0xFF;
        int rOff      = 4;
        int rLen      = rTotalLen;
        if (der[rOff] == 0x00) { rOff++; rLen--; }
        int sStart    = 4 + rTotalLen + 2;
        int sTotalLen = der[4 + rTotalLen + 1] & 0xFF;
        int sOff      = sStart;
        int sLen      = sTotalLen;
        if (der[sOff] == 0x00) { sOff++; sLen--; }
        byte[] out    = new byte[64];
        int rPad = 32 - rLen;
        if (rPad > 0) Arrays.fill(out, 0, rPad, (byte) 0);
        System.arraycopy(der, rOff, out, rPad, rLen);
        int sPad = 32 - sLen;
        if (sPad > 0) Arrays.fill(out, 32, 32 + sPad, (byte) 0);
        System.arraycopy(der, sOff, out, 32 + sPad, sLen);
        return out;
    }
}
