package com.psia.pkoc.core;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import com.upokecenter.cbor.CBORObject;

import org.bouncycastle.util.encoders.Hex;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.Arrays;

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
    public static final String KEY_ELEMENT_ID     = "aliro_access_doc_element_id"; // string
    public static final String KEY_DOC_MODE       = "aliro_access_doc_mode";      // "test" or "imported"
    public static final String KEY_DOC_VALID_FROM = "aliro_access_doc_valid_from"; // ISO-8601
    public static final String KEY_DOC_VALID_UNTIL= "aliro_access_doc_valid_until";// ISO-8601

    // Revocation Document SharedPreferences keys
    public static final String KEY_REVOC_DOC            = "aliro_revocation_doc";           // Base64 CBOR
    public static final String KEY_REVOC_ISSUER_PUB_KEY = "aliro_revoc_doc_issuer_pub_key"; // hex
    public static final String KEY_REVOC_ELEMENT_ID     = "aliro_revoc_doc_element_id";     // string

    // Aliro doc type and namespace constants
    public static final String DOCTYPE_ACCESS      = "aliro-a";
    public static final String NAMESPACE_ACCESS    = "aliro-a";

    // Aliro Revocation Document constants (per §7.6)
    public static final String DOCTYPE_REVOCATION  = "aliro-r";
    public static final String NAMESPACE_REVOCATION = "aliro-r";

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
    public static String generateTestDocument(Context context,
                                               byte[] credPubKeyBytes,
                                               String elementIdentifier,
                                               int validDays)
    {
        try
        {
            // 1. Generate issuer keypair
            KeyPair issuerKP = AliroCryptoProvider.generateEphemeralKeypair();
            if (issuerKP == null) return null;
            ECPublicKey issuerPub = (ECPublicKey) issuerKP.getPublic();
            byte[] issuerPubBytes = uncompressedPoint(issuerPub);

            // 2. Build AccessData CBOR per §7.3 — realistic employee badge data
            // so the Step-Up document shows meaningful content (Employee ID,
            // Access Rules, Schedules) in both the simulator and credential UIs.
            CBORObject accessData = buildRealisticAccessData();

            // 3. Build IssuerSignedItem per Table 7-2
            byte[] random = AliroCryptoProvider.generateRandom(16);
            int digestId = 0;
            CBORObject issuerSignedItem = buildIssuerSignedItem(
                    digestId, random, elementIdentifier, accessData);

            // 4. Wrap IssuerSignedItem in CBOR tag 24 per ISO 18013-5 §8.3.2.1.2.2
            byte[] itemBytes = issuerSignedItem.EncodeToBytes();
            CBORObject taggedItem = CBORObject.FromObjectAndTag(
                    CBORObject.FromObject(itemBytes), 24);
            // Digest is over the CBOR encoding of #6.24(bstr(IssuerSignedItem))
            // per ISO 18013-5 §9.1.2.5
            byte[] taggedItemBytes = taggedItem.EncodeToBytes();
            byte[] digest = sha256(taggedItemBytes);

            // 5. Build MobileSecurityObject per §7.2 + Table 7-1
            Instant now    = Instant.now();
            Instant until  = now.plusSeconds((long) validDays * 86400);
            CBORObject mso  = buildMSO(credPubKeyBytes, elementIdentifier,
                                       digestId, digest, now, until);

            // 6. COSE_Sign1 over MobileSecurityObject
            byte[] msoBytes  = mso.EncodeToBytes();
            byte[] signature = coseSign1(issuerKP.getPrivate(), msoBytes);
            if (signature == null) return null;

            // 7. Build IssuerAuth = COSE_Sign1 array
            CBORObject issuerAuth = buildCoseSign1(issuerPubBytes, msoBytes, signature);

            // 8. Build nameSpaces map: { "aliro-a": [#6.24(bstr(IssuerSignedItem))] }
            CBORObject nameSpaces = CBORObject.NewOrderedMap();
            CBORObject itemsArray = CBORObject.NewArray();
            itemsArray.Add(taggedItem);
            nameSpaces.Add(CBORObject.FromObject(NAMESPACE_ACCESS), itemsArray);

            // 9. Build issuerSigned: { "1": nameSpaces, "2": IssuerAuth }
            CBORObject issuerSigned = CBORObject.NewOrderedMap();
            issuerSigned.Add(CBORObject.FromObject("1"), nameSpaces);
            issuerSigned.Add(CBORObject.FromObject("2"), issuerAuth);

            // 10. Build full document: { "5": docType, "1": issuerSigned }
            CBORObject document = CBORObject.NewOrderedMap();
            // Keys must be in deterministic order per Aliro §7.2 / RFC 8949 §4.2.1
            document.Add(CBORObject.FromObject("1"), issuerSigned);
            document.Add(CBORObject.FromObject("5"), CBORObject.FromObject(DOCTYPE_ACCESS));

            // 11. Wrap in DeviceResponse: { "1": "1.0", "2": [document], "3": 0 }
            CBORObject docResponse = CBORObject.NewOrderedMap();
            docResponse.Add(CBORObject.FromObject("1"), CBORObject.FromObject("1.0"));
            CBORObject docs = CBORObject.NewArray();
            docs.Add(document);
            docResponse.Add(CBORObject.FromObject("2"), docs);
            docResponse.Add(CBORObject.FromObject("3"), CBORObject.FromObject(0));

            // 12. Store
            byte[] cborBytes = docResponse.EncodeToBytes();
            String b64       = Base64.encodeToString(cborBytes, Base64.DEFAULT);
            String issuerHex = Hex.toHexString(issuerPubBytes);

            SharedPreferences.Editor editor = context
                    .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
            editor.putString(KEY_ACCESS_DOC,      b64);
            editor.putString(KEY_ISSUER_PUB_KEY,  issuerHex);
            editor.putString(KEY_ELEMENT_ID,      elementIdentifier);
            editor.putString(KEY_DOC_MODE,        "test");
            editor.putString(KEY_DOC_VALID_FROM,  now.toString());
            editor.putString(KEY_DOC_VALID_UNTIL, until.toString());
            editor.apply();

            String summary = "Test document generated.\n"
                    + "Element: " + elementIdentifier + "\n"
                    + "Valid until: " + until.toString().substring(0, 10) + "\n"
                    + "Issuer key: " + issuerHex.substring(0, 16) + "...\n"
                    + "Size: " + cborBytes.length + " bytes";
            Log.d(TAG, "Generated test Access Document: " + cborBytes.length + " bytes");

            // 13. Also generate paired Revocation Document
            // Generate Revocation Document with the SAME issuer keypair so both
            // documents verify against the same dut_credential_issuer_public_key.
            String revocResult = generateRevocationDocument(context, elementIdentifier, validDays,
                    issuerKP, issuerPubBytes);
            if (revocResult != null)
            {
                Log.d(TAG, "Generated paired Revocation Document");
            }
            else
            {
                Log.w(TAG, "Revocation Document generation failed (non-fatal)");
            }

            // 14. Initialize mailbox with structured sample data per Aliro §18
            // so the simulator displays meaningful Reader Config / Door Status.
            // Only initialize if mailbox is empty — don't overwrite harness test data.
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
                    Log.d(TAG, "Initialized mailbox with structured sample data (" + sampleMailbox.length + " bytes)");
                }
                else
                {
                    Log.d(TAG, "Mailbox already has data — skipping sample initialization");
                }
            }
            catch (Exception mbEx)
            {
                Log.w(TAG, "Mailbox sample initialization failed (non-fatal)", mbEx);
            }

            return summary;
        }
        catch (Exception e)
        {
            Log.e(TAG, "generateTestDocument failed", e);
            return null;
        }
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
     * @param context           Application context
     * @param elementIdentifier DataElementIdentifier (same as paired Access Document)
     * @param validDays         Number of days the document should be valid
     * @return Summary string for display, or null on failure
     */
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
        try
        {
            // 1. Generate issuer keypair
            KeyPair issuerKP = AliroCryptoProvider.generateEphemeralKeypair();
            if (issuerKP == null) return null;
            ECPublicKey issuerPub = (ECPublicKey) issuerKP.getPublic();
            byte[] issuerPubBytes = uncompressedPoint(issuerPub);

            // 2. Build realistic AccessData CBOR per §7.3
            CBORObject accessData = buildRealisticAccessData();

            // 3. Build IssuerSignedItem per Table 7-2
            byte[] random  = AliroCryptoProvider.generateRandom(16);
            int    digestId = 0;
            CBORObject issuerSignedItem = buildIssuerSignedItem(
                    digestId, random, elementIdentifier, accessData);

            // 4. Wrap IssuerSignedItem in CBOR tag 24 per ISO 18013-5 §8.3.2.1.2.2
            byte[] itemBytes = issuerSignedItem.EncodeToBytes();
            CBORObject taggedItem = CBORObject.FromObjectAndTag(
                    CBORObject.FromObject(itemBytes), 24);
            // Digest is over the CBOR encoding of #6.24(bstr(IssuerSignedItem))
            // per ISO 18013-5 §9.1.2.5
            byte[] taggedItemBytes = taggedItem.EncodeToBytes();
            byte[] digest = sha256(taggedItemBytes);

            // 5. Build MobileSecurityObject
            Instant now   = Instant.now();
            Instant until = now.plusSeconds((long) validDays * 86400);
            CBORObject mso = buildMSO(credPubKeyBytes, elementIdentifier,
                                       digestId, digest, now, until);

            // 6. COSE_Sign1 over MSO
            byte[] msoBytes  = mso.EncodeToBytes();
            byte[] signature = coseSign1(issuerKP.getPrivate(), msoBytes);
            if (signature == null) return null;

            // 7. Build IssuerAuth COSE_Sign1 array
            CBORObject issuerAuth = buildCoseSign1(issuerPubBytes, msoBytes, signature);

            // 8. nameSpaces
            CBORObject nameSpaces = CBORObject.NewOrderedMap();
            CBORObject itemsArray = CBORObject.NewArray();
            itemsArray.Add(taggedItem);
            nameSpaces.Add(CBORObject.FromObject(NAMESPACE_ACCESS), itemsArray);

            // 9. issuerSigned
            CBORObject issuerSigned = CBORObject.NewOrderedMap();
            issuerSigned.Add(CBORObject.FromObject("1"), nameSpaces);
            issuerSigned.Add(CBORObject.FromObject("2"), issuerAuth);

            // 10. Document
            CBORObject document = CBORObject.NewOrderedMap();
            // Keys must be in deterministic order per Aliro §7.2 / RFC 8949 §4.2.1
            document.Add(CBORObject.FromObject("1"), issuerSigned);
            document.Add(CBORObject.FromObject("5"), CBORObject.FromObject(DOCTYPE_ACCESS));

            // 11. DeviceResponse
            CBORObject docResponse = CBORObject.NewOrderedMap();
            docResponse.Add(CBORObject.FromObject("1"), CBORObject.FromObject("1.0"));
            CBORObject docs = CBORObject.NewArray();
            docs.Add(document);
            docResponse.Add(CBORObject.FromObject("2"), docs);
            docResponse.Add(CBORObject.FromObject("3"), CBORObject.FromObject(0));

            // 12. Store
            byte[] cborBytes = docResponse.EncodeToBytes();
            String b64       = Base64.encodeToString(cborBytes, Base64.DEFAULT);
            String issuerHex = Hex.toHexString(issuerPubBytes);

            SharedPreferences.Editor editor = context
                    .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
            editor.putString(KEY_ACCESS_DOC,      b64);
            editor.putString(KEY_ISSUER_PUB_KEY,  issuerHex);
            editor.putString(KEY_ELEMENT_ID,      elementIdentifier);
            editor.putString(KEY_DOC_MODE,        "sample");
            editor.putString(KEY_DOC_VALID_FROM,  now.toString());
            editor.putString(KEY_DOC_VALID_UNTIL, until.toString());
            editor.apply();

            String summary = "Sample document generated.\n"
                    + "ID: ELATEC001\n"
                    + "Element: " + elementIdentifier + "\n"
                    + "Rules: 2 (weekday + weekend)\n"
                    + "Schedules: Mon-Fri 07:00-19:00, Sat-Sun 09:00-17:00\n"
                    + "Valid until: " + until.toString().substring(0, 10) + "\n"
                    + "Issuer key: " + issuerHex.substring(0, 16) + "...\n"
                    + "Size: " + cborBytes.length + " bytes";
            Log.d(TAG, "Generated realistic sample Access Document: " + cborBytes.length + " bytes");
            return summary;
        }
        catch (Exception e)
        {
            Log.e(TAG, "generateRealisticSampleDocument failed", e);
            return null;
        }
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

            // Extract element identifier from first IssuerSignedItem if possible
            String elementId = extractElementId(doc);
            String validUntil = extractValidUntil(doc);

            SharedPreferences.Editor editor = context
                    .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
            editor.putString(KEY_ACCESS_DOC,      base64Cbor.trim());
            editor.putString(KEY_ISSUER_PUB_KEY,  issuerPubHex != null ? issuerPubHex.toLowerCase().trim() : "");
            editor.putString(KEY_ELEMENT_ID,      elementId != null ? elementId : "access");
            editor.putString(KEY_DOC_MODE,        "imported");
            editor.putString(KEY_DOC_VALID_FROM,  "");
            editor.putString(KEY_DOC_VALID_UNTIL, validUntil != null ? validUntil : "");
            editor.apply();

            String summary = "Document imported.\n"
                    + "Element: " + (elementId != null ? elementId : "(unknown)") + "\n"
                    + "Valid until: " + (validUntil != null ? validUntil : "(unknown)") + "\n"
                    + "Size: " + cborBytes.length + " bytes";
            Log.d(TAG, "Imported Access Document: " + cborBytes.length + " bytes");
            return summary;
        }
        catch (Exception e)
        {
            Log.e(TAG, "importDocument failed", e);
            return null;
        }
    }

    /**
     * Clear the stored Access Document.
     */
    public static void clearDocument(Context context)
    {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
               .edit()
               .remove(KEY_ACCESS_DOC)
               .remove(KEY_ISSUER_PUB_KEY)
               .remove(KEY_ELEMENT_ID)
               .remove(KEY_DOC_MODE)
               .remove(KEY_DOC_VALID_FROM)
               .remove(KEY_DOC_VALID_UNTIL)
               .apply();
        Log.d(TAG, "Access Document cleared");
    }

    /**
     * Clear the stored Revocation Document.
     */
    public static void clearRevocationDocument(Context context)
    {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
               .edit()
               .remove(KEY_REVOC_DOC)
               .remove(KEY_REVOC_ISSUER_PUB_KEY)
               .remove(KEY_REVOC_ELEMENT_ID)
               .apply();
        Log.d(TAG, "Revocation Document cleared");
    }

    /**
     * Check whether an Access Document is currently stored.
     */
    public static boolean hasDocument(Context context)
    {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                      .contains(KEY_ACCESS_DOC);
    }

    /**
     * Check whether a Revocation Document is currently stored.
     */
    public static boolean hasRevocationDocument(Context context)
    {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                      .contains(KEY_REVOC_DOC);
    }

    /**
     * Get the stored Access Document CBOR bytes, or null if none.
     */
    public static byte[] getDocumentBytes(Context context)
    {
        String b64 = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                            .getString(KEY_ACCESS_DOC, null);
        if (b64 == null) return null;
        try { return Base64.decode(b64, Base64.DEFAULT); }
        catch (Exception e) { return null; }
    }

    /**
     * Get the stored Revocation Document CBOR bytes, or null if none.
     */
    public static byte[] getRevocationDocumentBytes(Context context)
    {
        String b64 = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                            .getString(KEY_REVOC_DOC, null);
        if (b64 == null) return null;
        try { return Base64.decode(b64, Base64.DEFAULT); }
        catch (Exception e) { return null; }
    }

    /**
     * Get the stored element identifier (DataElementIdentifier) for the DeviceRequest.
     */
    public static String getElementIdentifier(Context context)
    {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                      .getString(KEY_ELEMENT_ID, "access");
    }

    /**
     * Get the stored element identifier for the Revocation Document.
     */
    public static String getRevocationElementIdentifier(Context context)
    {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                      .getString(KEY_REVOC_ELEMENT_ID, "access");
    }

    /**
     * Get the stored issuer public key as 65-byte uncompressed bytes, or null if none.
     */
    public static byte[] getIssuerPublicKeyBytes(Context context)
    {
        String hex = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                            .getString(KEY_ISSUER_PUB_KEY, null);
        if (hex == null || hex.isEmpty()) return null;
        try { return Hex.decode(hex); }
        catch (Exception e) { return null; }
    }

    // =========================================================================
    // AccessData builders
    // =========================================================================

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
     *       0: 1745971200,              // startPeriod: 2025-04-30 00:00:00 UTC
     *       1: 1777507200,              // endPeriod:   2026-04-30 00:00:00 UTC
     *       2: [43200, 0x1F, 2, 1, 0], // 12h, Mon-Fri, Weekly, every 1 week
     *       3: 0x01                     // flags: Time_in_UTC
     *     },
     *     {                             // Schedule 1: Sat-Sun 09:00-17:00 UTC
     *       0: 1745971200,
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
        // startPeriod: 2025-04-30 00:00:00 UTC = 1745971200
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
        schedule0.Add(CBORObject.FromObject(0), CBORObject.FromObject(1745971200L)); // startPeriod
        schedule0.Add(CBORObject.FromObject(1), CBORObject.FromObject(1777507200L)); // endPeriod
        schedule0.Add(CBORObject.FromObject(2), recRule0);                            // recurrenceRule
        schedule0.Add(CBORObject.FromObject(3), CBORObject.FromObject(0x01));         // flags: UTC

        // ---- Schedule 1: Weekend 09:00-17:00 UTC (Sat-Sun, recurring weekly) ----
        // durationSeconds: 8 * 3600 = 28800
        // dayMask: Sat+Sun = bits 5,6 = 0x60
        CBORObject recRule1 = CBORObject.NewArray();
        recRule1.Add(CBORObject.FromObject(28800)); // durationSeconds (8 h)
        recRule1.Add(CBORObject.FromObject(0x60));  // dayMask: Sat+Sun
        recRule1.Add(CBORObject.FromObject(2));     // pattern: Weekly
        recRule1.Add(CBORObject.FromObject(1));     // interval: every 1 week
        recRule1.Add(CBORObject.FromObject(0));     // ordinal: unused

        CBORObject schedule1 = CBORObject.NewOrderedMap();
        schedule1.Add(CBORObject.FromObject(0), CBORObject.FromObject(1745971200L)); // startPeriod
        schedule1.Add(CBORObject.FromObject(1), CBORObject.FromObject(1777507200L)); // endPeriod
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
