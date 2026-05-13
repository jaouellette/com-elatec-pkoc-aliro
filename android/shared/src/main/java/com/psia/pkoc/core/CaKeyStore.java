package com.psia.pkoc.core;

import android.content.Context;
import android.content.SharedPreferences;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONArray;
import org.json.JSONObject;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.math.BigInteger;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Per-group_id Reader System Issuer CA keypair store for Aliro Flow #2
 * (cert-based reader enrollment).
 *
 * Background. Aliro 1.0 §6.2 allows the reader_group_identifier_key to bind
 * to either the reader's own public key (Flow #1, self-signed) or to the
 * Reader System Issuer CA public key (Flow #2, cert-signed). In Flow #2 the
 * App side acts as the CA — it owns a CA keypair, signs profile0000 reader
 * certificates per §13.3 for readers that present themselves over the
 * enrollment AID, and stores the matching CA pub key on its own
 * user-device side so it can verify the cert at AUTH1 time later.
 *
 * Storage model. One CA keypair per reader_group_identifier (16 bytes).
 * Lookup by group_id at sign time and at AUTH0/AUTH1 verify time. Keys
 * persist across app restarts. Storage lives in its own SharedPreferences
 * file ({@code aliro_ca_keystore.xml}) so that the existing single-credential
 * store ({@code AliroProvisioning.xml}) is untouched and Flow #1 keeps
 * working unchanged.
 *
 * Format. The entire keystore is serialised as a single JSON document under
 * a single prefs key ({@code entries}). Entries are JSON objects with
 * {@code groupIdHex}, {@code caPrivHex}, {@code caPubHex}, {@code createdAtMs}
 * and {@code label}. Number of entries is expected to be small (dozens at
 * most for a demonstrator), so deserialise-on-read / serialise-on-write is
 * cheap enough not to need indexing.
 *
 * Threading. All public methods are {@code synchronized} on the class to
 * make the read-modify-write paths atomic. The HCE service runs on its
 * own binder thread and the UI runs on the main thread; both will hit this
 * class.
 *
 * Out of scope. This is not a HSM. The CA private keys are stored as hex
 * strings in plaintext SharedPreferences just like the existing
 * {@code AliroProvisioningManager} stores reader private keys. Fine for a
 * demonstrator; not appropriate for production deployments.
 */
public final class CaKeyStore
{
    private static final String TAG = "CaKeyStore";

    /** Separate prefs file, kept distinct from the existing single-credential store. */
    public static final String PREFS_NAME = "aliro_ca_keystore";

    /** Single JSON-array key holding all entries. */
    private static final String KEY_ENTRIES = "entries";

    // JSON field names — keep stable across versions, see migration note below.
    private static final String F_GROUP_ID_HEX  = "groupIdHex";
    private static final String F_CA_PRIV_HEX   = "caPrivHex";
    private static final String F_CA_PUB_HEX    = "caPubHex";
    private static final String F_CREATED_AT_MS = "createdAtMs";
    private static final String F_LABEL         = "label";
    /** Reader's own public key (65 bytes uncompressed). Added for Flow #2 AUTH1
     *  signature verification per Aliro §8.3.3.4.5 no-cert branch. Nullable in
     *  entries created before this field was introduced. */
    private static final String F_READER_PUB_HEX = "readerPubHex";

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private CaKeyStore() { /* no instances */ }

    // =========================================================================
    // Public types
    // =========================================================================

    /**
     * One entry in the keystore. Immutable.
     */
    public static final class CaKeyEntry
    {
        public final byte[] groupId;     // 16 bytes
        public final byte[] caPriv;      // 32 bytes raw scalar
        public final byte[] caPub;       // 65 bytes uncompressed (0x04 || X || Y)
        /**
         * Reader's own public key (65 bytes uncompressed). Captured at
         * enrollment time from the 0xE2 payload so the App side can later
         * verify the reader signature at AUTH1 time without requiring the
         * reader to include the cert in every transaction (Aliro §8.3.3.4.5
         * no-cert branch). May be null for entries created before this
         * field was added, or in fleet scenarios where multiple readers
         * share a group_id.
         */
        public final byte[] readerPub;
        public final long   createdAtMs;
        public final String label;

        CaKeyEntry(byte[] groupId, byte[] caPriv, byte[] caPub, byte[] readerPub,
                   long createdAtMs, String label)
        {
            this.groupId     = groupId;
            this.caPriv      = caPriv;
            this.caPub       = caPub;
            this.readerPub   = readerPub;
            this.createdAtMs = createdAtMs;
            this.label       = label;
        }

        public String groupIdHex() { return Hex.toHexString(groupId); }
        public String caPubHex()   { return Hex.toHexString(caPub); }
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Look up a CA entry by group_id, generating a new P-256 keypair and
     * persisting it if none exists. Used at INS 0xE2 approve time.
     *
     * If a {@code readerPub} is provided, it is stored alongside the CA
     * keypair so the App side can later verify the reader signature at
     * AUTH1 time per §8.3.3.4.5 without requiring the cert in every
     * transaction. If an entry already exists for this group_id and the
     * caller provides a {@code readerPub}, the stored reader pub is
     * UPDATED to the new value (most-recently-enrolled wins). Pass null
     * for {@code readerPub} to leave any stored value untouched.
     *
     * @param context  Android context (any).
     * @param groupId  16-byte reader_group_identifier.
     * @param readerPub 65-byte uncompressed reader public key, or null if
     *                  not available / not to be updated.
     * @return existing or newly-created entry; never null on success.
     * @throws Exception on keygen or persistence failure.
     */
    public static synchronized CaKeyEntry getOrCreateCAKey(Context context, byte[] groupId,
                                                            byte[] readerPub)
            throws Exception
    {
        validateGroupId(groupId);
        if (readerPub != null && (readerPub.length != 65 || readerPub[0] != 0x04))
        {
            throw new IllegalArgumentException(
                    "readerPub must be 65-byte uncompressed (0x04 || X || Y) or null");
        }

        CaKeyEntry existing = getCAKeyInternal(context, groupId);
        if (existing != null)
        {
            // If caller provided a reader pub and it differs from what's
            // stored, update the stored value (most-recently-enrolled wins).
            // This is fine for single-reader-per-group_id deployments; in
            // fleet deployments where multiple readers share a group_id the
            // stored reader pub becomes ambiguous and the App side will
            // need to rely on cert-in-AUTH1 instead (which is unaffected
            // by the value stored here).
            if (readerPub != null && !java.util.Arrays.equals(readerPub, existing.readerPub))
            {
                CaKeyEntry updated = new CaKeyEntry(
                        existing.groupId, existing.caPriv, existing.caPub,
                        readerPub.clone(), existing.createdAtMs, existing.label);
                persistReplace(context, updated);
                AliroDiagnosticLog.d(TAG, "getOrCreateCAKey: updated readerPub on existing entry for groupId="
                        + Hex.toHexString(groupId).substring(0, 8) + "...");
                return updated;
            }
            AliroDiagnosticLog.d(TAG, "getOrCreateCAKey: existing entry for groupId="
                    + Hex.toHexString(groupId).substring(0, 8) + "...");
            return existing;
        }

        // Generate a fresh P-256 keypair.
        KeyPair  kp     = generateP256KeyPair();
        byte[]   caPub  = uncompressedPub(kp);
        byte[]   caPriv = privateScalar(kp);
        long     now    = System.currentTimeMillis();
        String   label  = defaultLabelFor(groupId);

        CaKeyEntry entry = new CaKeyEntry(
                groupId,
                caPriv,
                caPub,
                readerPub != null ? readerPub.clone() : null,
                now,
                label);
        persistAppend(context, entry);

        AliroDiagnosticLog.i(TAG, "getOrCreateCAKey: generated new CA keypair for groupId="
                + Hex.toHexString(groupId).substring(0, 8) + "..., label='" + label + "'"
                + (readerPub != null ? ", readerPub stored" : ", no readerPub provided"));
        return entry;
    }

    /**
     * Backwards-compatible overload — equivalent to
     * {@link #getOrCreateCAKey(Context, byte[], byte[])} with {@code readerPub=null}.
     * Used by callers that don't have the reader pub to hand (currently none in
     * the codebase, but kept for future flexibility).
     */
    public static synchronized CaKeyEntry getOrCreateCAKey(Context context, byte[] groupId)
            throws Exception
    {
        return getOrCreateCAKey(context, groupId, null);
    }

    /**
     * Read-only lookup. Returns null if no entry exists.
     */
    public static synchronized CaKeyEntry getCAKey(Context context, byte[] groupId)
    {
        try { validateGroupId(groupId); } catch (Exception e) { return null; }
        return getCAKeyInternal(context, groupId);
    }

    /**
     * Convenience helper for AUTH0 / AUTH1 verify paths: returns just the
     * 65-byte uncompressed CA public key for the given group_id, or null.
     */
    public static synchronized byte[] getCAPubKeyForGroupId(Context context, byte[] groupId)
    {
        CaKeyEntry e = getCAKey(context, groupId);
        return (e != null) ? e.caPub : null;
    }

    /**
     * Convenience helper for AUTH1 signature verification (Aliro §8.3.3.4.5
     * no-cert branch): returns the 65-byte uncompressed reader public key
     * stored for the given group_id at enrollment time, or null if no entry
     * exists or the entry has no stored reader pub.
     */
    public static synchronized byte[] getReaderPubKeyForGroupId(Context context, byte[] groupId)
    {
        CaKeyEntry e = getCAKey(context, groupId);
        return (e != null) ? e.readerPub : null;
    }

    /**
     * List all entries (for UI display). Returns an empty list if the
     * keystore is empty or unreadable.
     */
    public static synchronized List<CaKeyEntry> listAll(Context context)
    {
        List<CaKeyEntry> out = new ArrayList<>();
        try
        {
            JSONArray arr = readEntriesArray(context);
            for (int i = 0; i < arr.length(); i++)
            {
                CaKeyEntry e = parseEntry(arr.getJSONObject(i));
                if (e != null) out.add(e);
            }
        }
        catch (Exception ex)
        {
            AliroDiagnosticLog.e(TAG, "listAll: failed to parse keystore", ex);
        }
        return out;
    }

    /**
     * Update the user-friendly label on an existing entry. No-op if the
     * entry doesn't exist.
     *
     * @return true if updated, false if entry not found.
     */
    public static synchronized boolean setLabel(Context context, byte[] groupId, String newLabel)
    {
        try { validateGroupId(groupId); } catch (Exception e) { return false; }
        if (newLabel == null) newLabel = "";

        try
        {
            JSONArray arr = readEntriesArray(context);
            String targetHex = Hex.toHexString(groupId).toLowerCase(Locale.US);
            for (int i = 0; i < arr.length(); i++)
            {
                JSONObject obj = arr.getJSONObject(i);
                String hex = obj.optString(F_GROUP_ID_HEX, "").toLowerCase(Locale.US);
                if (targetHex.equals(hex))
                {
                    obj.put(F_LABEL, newLabel);
                    writeEntriesArray(context, arr);
                    AliroDiagnosticLog.d(TAG, "setLabel: renamed " + hex.substring(0, 8)
                            + "... to '" + newLabel + "'");
                    return true;
                }
            }
            return false;
        }
        catch (Exception ex)
        {
            AliroDiagnosticLog.e(TAG, "setLabel failed", ex);
            return false;
        }
    }

    /**
     * Remove the entry for the given group_id.
     *
     * @return true if removed, false if entry not found.
     */
    public static synchronized boolean delete(Context context, byte[] groupId)
    {
        try { validateGroupId(groupId); } catch (Exception e) { return false; }

        try
        {
            JSONArray arr = readEntriesArray(context);
            String targetHex = Hex.toHexString(groupId).toLowerCase(Locale.US);
            JSONArray rebuilt = new JSONArray();
            boolean removed = false;
            for (int i = 0; i < arr.length(); i++)
            {
                JSONObject obj = arr.getJSONObject(i);
                String hex = obj.optString(F_GROUP_ID_HEX, "").toLowerCase(Locale.US);
                if (targetHex.equals(hex))
                {
                    removed = true;
                    continue;  // skip this one
                }
                rebuilt.put(obj);
            }
            if (removed)
            {
                writeEntriesArray(context, rebuilt);
                AliroDiagnosticLog.i(TAG, "delete: removed entry for groupId="
                        + targetHex.substring(0, 8) + "...");
            }
            return removed;
        }
        catch (Exception ex)
        {
            AliroDiagnosticLog.e(TAG, "delete failed", ex);
            return false;
        }
    }

    /**
     * Wipe every entry.
     */
    public static synchronized void clearAll(Context context)
    {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .remove(KEY_ENTRIES)
                .apply();
        AliroDiagnosticLog.i(TAG, "clearAll: wiped CA keystore");
    }

    /**
     * Export the entire keystore as a JSON string for backup or fleet
     * distribution. Format intentionally matches the on-disk schema so a
     * future import path can deserialise the same JSON.
     *
     * @return a JSON object string containing {@code v}, {@code type},
     *         {@code entries}; or null on failure.
     */
    public static synchronized String exportJson(Context context)
    {
        try
        {
            JSONObject out = new JSONObject();
            out.put("v",       1);
            out.put("type",    "aliro_ca_keystore");
            out.put("entries", readEntriesArray(context));
            return out.toString();
        }
        catch (Exception ex)
        {
            AliroDiagnosticLog.e(TAG, "exportJson failed", ex);
            return null;
        }
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    private static CaKeyEntry getCAKeyInternal(Context context, byte[] groupId)
    {
        try
        {
            JSONArray arr = readEntriesArray(context);
            String targetHex = Hex.toHexString(groupId).toLowerCase(Locale.US);
            for (int i = 0; i < arr.length(); i++)
            {
                JSONObject obj = arr.getJSONObject(i);
                String hex = obj.optString(F_GROUP_ID_HEX, "").toLowerCase(Locale.US);
                if (targetHex.equals(hex)) return parseEntry(obj);
            }
            return null;
        }
        catch (Exception ex)
        {
            AliroDiagnosticLog.e(TAG, "getCAKeyInternal failed", ex);
            return null;
        }
    }

    private static void persistAppend(Context context, CaKeyEntry entry) throws Exception
    {
        JSONArray arr = readEntriesArray(context);
        arr.put(entryToJson(entry));
        writeEntriesArray(context, arr);
    }

    /** Replace an existing entry matching the given group_id with {@code entry}. */
    private static void persistReplace(Context context, CaKeyEntry entry) throws Exception
    {
        JSONArray arr = readEntriesArray(context);
        String targetHex = Hex.toHexString(entry.groupId).toLowerCase(Locale.US);
        JSONArray rebuilt = new JSONArray();
        boolean replaced = false;
        for (int i = 0; i < arr.length(); i++)
        {
            JSONObject obj = arr.getJSONObject(i);
            String hex = obj.optString(F_GROUP_ID_HEX, "").toLowerCase(Locale.US);
            if (targetHex.equals(hex) && !replaced)
            {
                rebuilt.put(entryToJson(entry));
                replaced = true;
            }
            else
            {
                rebuilt.put(obj);
            }
        }
        if (!replaced) rebuilt.put(entryToJson(entry));
        writeEntriesArray(context, rebuilt);
    }

    private static JSONObject entryToJson(CaKeyEntry entry) throws Exception
    {
        JSONObject obj = new JSONObject();
        obj.put(F_GROUP_ID_HEX,  Hex.toHexString(entry.groupId).toLowerCase(Locale.US));
        obj.put(F_CA_PRIV_HEX,   Hex.toHexString(entry.caPriv).toLowerCase(Locale.US));
        obj.put(F_CA_PUB_HEX,    Hex.toHexString(entry.caPub).toLowerCase(Locale.US));
        if (entry.readerPub != null)
        {
            obj.put(F_READER_PUB_HEX, Hex.toHexString(entry.readerPub).toLowerCase(Locale.US));
        }
        obj.put(F_CREATED_AT_MS, entry.createdAtMs);
        obj.put(F_LABEL,         entry.label != null ? entry.label : "");
        return obj;
    }

    private static JSONArray readEntriesArray(Context context) throws Exception
    {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String stored = prefs.getString(KEY_ENTRIES, null);
        if (stored == null || stored.isEmpty()) return new JSONArray();
        return new JSONArray(stored);
    }

    private static void writeEntriesArray(Context context, JSONArray arr)
    {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_ENTRIES, arr.toString())
                .apply();
    }

    private static CaKeyEntry parseEntry(JSONObject obj)
    {
        try
        {
            String groupIdHex  = obj.optString(F_GROUP_ID_HEX, "");
            String caPrivHex   = obj.optString(F_CA_PRIV_HEX,  "");
            String caPubHex    = obj.optString(F_CA_PUB_HEX,   "");
            String readerPubHex= obj.optString(F_READER_PUB_HEX, "");
            long   createdAt   = obj.optLong  (F_CREATED_AT_MS, 0L);
            String label       = obj.optString(F_LABEL, "");

            byte[] groupId = Hex.decode(groupIdHex);
            byte[] caPriv  = Hex.decode(caPrivHex);
            byte[] caPub   = Hex.decode(caPubHex);
            byte[] readerPub = null;
            if (!readerPubHex.isEmpty())
            {
                try
                {
                    byte[] candidate = Hex.decode(readerPubHex);
                    if (candidate.length == 65 && candidate[0] == 0x04)
                    {
                        readerPub = candidate;
                    }
                    else
                    {
                        AliroDiagnosticLog.w(TAG, "parseEntry: readerPub malformed (len="
                                + candidate.length + "), treating as absent");
                    }
                }
                catch (Exception ex)
                {
                    AliroDiagnosticLog.w(TAG, "parseEntry: readerPub hex decode failed: " + ex.getMessage());
                }
            }

            if (groupId.length != 16 || caPriv.length != 32 || caPub.length != 65 || caPub[0] != 0x04)
            {
                AliroDiagnosticLog.w(TAG, "parseEntry: malformed entry, skipping");
                return null;
            }

            if (label.isEmpty()) label = defaultLabelFor(groupId);
            return new CaKeyEntry(groupId, caPriv, caPub, readerPub, createdAt, label);
        }
        catch (Exception ex)
        {
            AliroDiagnosticLog.w(TAG, "parseEntry: " + ex.getMessage());
            return null;
        }
    }

    private static String defaultLabelFor(byte[] groupId)
    {
        // First 8 hex chars of group_id, per Gate 2 plan Q1 answer.
        return Hex.toHexString(groupId).substring(0, 8);
    }

    private static void validateGroupId(byte[] groupId)
    {
        if (groupId == null || groupId.length != 16)
        {
            throw new IllegalArgumentException(
                    "groupId must be 16 bytes (got " + (groupId == null ? "null" : groupId.length) + ")");
        }
    }

    // -------------------------------------------------------------------------
    // P-256 keygen helpers, mirroring the BouncyCastle pattern used in
    // AliroProvisioningManager. Kept inline here so this class has no
    // cross-file dependency on private helpers in that class.
    // -------------------------------------------------------------------------

    private static KeyPair generateP256KeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return kpg.generateKeyPair();
    }

    private static byte[] uncompressedPub(KeyPair kp)
    {
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        byte[] x = toBytes32(pub.getW().getAffineX());
        byte[] y = toBytes32(pub.getW().getAffineY());
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(x, 0, out, 1,  32);
        System.arraycopy(y, 0, out, 33, 32);
        return out;
    }

    private static byte[] privateScalar(KeyPair kp) throws Exception
    {
        // BouncyCastle ECPrivateKey exposes getD() directly.
        java.security.PrivateKey priv = kp.getPrivate();
        if (priv instanceof org.bouncycastle.jce.interfaces.ECPrivateKey)
        {
            org.bouncycastle.jce.interfaces.ECPrivateKey bcPriv =
                    (org.bouncycastle.jce.interfaces.ECPrivateKey) priv;
            return toBytes32(bcPriv.getD());
        }
        // Fallback: parse PKCS#8 encoding. Mirrors AliroProvisioningManager.
        byte[] encoded = priv.getEncoded();
        org.bouncycastle.asn1.ASN1InputStream asn1in =
                new org.bouncycastle.asn1.ASN1InputStream(encoded);
        org.bouncycastle.asn1.ASN1Sequence pkcs8 =
                (org.bouncycastle.asn1.ASN1Sequence) asn1in.readObject();
        asn1in.close();
        byte[] ecPrivDer = org.bouncycastle.asn1.ASN1OctetString.getInstance(
                pkcs8.getObjectAt(2)).getOctets();
        org.bouncycastle.asn1.ASN1InputStream asn1in2 =
                new org.bouncycastle.asn1.ASN1InputStream(ecPrivDer);
        org.bouncycastle.asn1.ASN1Sequence ecPriv =
                (org.bouncycastle.asn1.ASN1Sequence) asn1in2.readObject();
        asn1in2.close();
        byte[] privOctets = org.bouncycastle.asn1.ASN1OctetString.getInstance(
                ecPriv.getObjectAt(1)).getOctets();
        return toBytes32(new BigInteger(1, privOctets));
    }

    private static byte[] toBytes32(BigInteger v)
    {
        byte[] raw = v.toByteArray();
        if (raw.length == 32) return raw;
        if (raw.length == 33 && raw[0] == 0)
        {
            byte[] out = new byte[32];
            System.arraycopy(raw, 1, out, 0, 32);
            return out;
        }
        if (raw.length < 32)
        {
            byte[] out = new byte[32];
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
            return out;
        }
        throw new IllegalArgumentException("BigInteger too large for 32-byte field: " + raw.length);
    }
}
