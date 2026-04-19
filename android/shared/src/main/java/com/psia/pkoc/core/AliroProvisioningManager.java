package com.psia.pkoc.core;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import org.json.JSONObject;

/**
 * AliroProvisioningManager — core provisioning engine for the Aliro Real Credential
 * (Option A).
 *
 * The credential app acts as both the Issuer and the credential device.
 * Provisioning generates a complete Issuer CA + reader keypair/certificate
 * and stores everything needed for strict-mode reader validation and
 * for export to a physical reader device via JSON / QR code.
 *
 * Profile0000 compressed certificate encoding follows Aliro 1.0 spec §13.3
 * (26-42802-001 pages 166-168) ASN.1 schema with IMPLICIT TAGS:
 *
 *   Profile0000 ::= SEQUENCE {
 *       profile    OCTET STRING (SIZE (2)),     -- raw 0x04 tag, value 0x0000
 *       data       Profile0000Data              -- inner SEQUENCE
 *   }
 *
 *   Profile0000Data ::= SEQUENCE {
 *       serialNumber  [0] OCTET STRING (SIZE (1..20)) OPTIONAL,
 *       issuer        [1] OCTET STRING (SIZE (1..32)) OPTIONAL,
 *       notBefore     [2] OCTET STRING (SIZE (13..15)) OPTIONAL,
 *       notAfter      [3] OCTET STRING (SIZE (13..15)) OPTIONAL,
 *       subject       [4] OCTET STRING (SIZE (1..32)) OPTIONAL,
 *       publicKey     [5] OCTET STRING,
 *       signature     [6] OCTET STRING
 *   }
 *
 * All preferences are stored in the "AliroProvisioning" SharedPreferences file.
 */
public class AliroProvisioningManager
{
    private static final String TAG = "AliroProvisioning";

    // -------------------------------------------------------------------------
    // SharedPreferences key constants
    // -------------------------------------------------------------------------
    public static final String PREFS_NAME           = "AliroProvisioning";

    private static final String KEY_ISSUER_CA_PRIV  = "issuer_ca_private_key";
    private static final String KEY_ISSUER_CA_PUB   = "issuer_ca_public_key";
    private static final String KEY_READER_PRIV     = "reader_private_key";
    private static final String KEY_READER_ID       = "reader_identifier";
    private static final String KEY_READER_CERT     = "reader_cert_compressed";
    private static final String KEY_READER_GROUP_ID = "reader_group_id";
    private static final String KEY_PROVISIONED     = "provisioned";
    private static final String KEY_STRICT_MODE     = "strict_mode";
    private static final String KEY_READER_PUB_KEY  = "test_harness_reader_pub_key";

    // BouncyCastle OIDs
    private static final String OID_SECP256R1          = "1.2.840.10045.3.1.7";
    private static final String OID_EC_PUBLIC_KEY      = "1.2.840.10045.2.1";
    private static final String OID_ECDSA_SHA256        = "1.2.840.10045.4.3.2";

    // Aliro profile0000 identifier bytes (§13.3)
    private static final byte[] PROFILE_ID = { 0x00, 0x00 };

    // Default field values per §13.3 (used when fields are omitted in the compressed cert)
    private static final byte[] DEFAULT_SERIAL     = { 0x01 };
    private static final byte[] DEFAULT_ISSUER     = "issuer".getBytes();
    private static final byte[] DEFAULT_NOT_BEFORE = "200101000000Z".getBytes();
    private static final byte[] DEFAULT_NOT_AFTER  = "490101000000Z".getBytes();
    private static final byte[] DEFAULT_SUBJECT    = "subject".getBytes();

    // -------------------------------------------------------------------------
    // Static initializer — ensure BC provider is registered
    // -------------------------------------------------------------------------
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Main entry point. Generates all keys, derives identifiers, builds the
     * reader certificate in profile0000 compressed format, and stores everything
     * in SharedPreferences.
     *
     * @param context Android context
     * @return Summary string on success, null on failure
     */
    public static String provisionCredential(Context context)
    {
        try
        {
            // ------------------------------------------------------------------
            // 1. Generate a single P-256 keypair for the reader.
            //
            // Per Aliro §6.2, the reader_group_identifier_key SHALL be exactly
            // one of: (a) Reader System Issuer CA public key, or (b) the
            // reader's own public key. Using the same key for both (self-signed
            // cert) satisfies both options and allows a single harness config
            // to work across no-cert and cert test flows.
            // ------------------------------------------------------------------
            KeyPair readerKeyPair   = generateP256KeyPair();
            byte[] readerPubUncomp  = getUncompressedPublicKey(readerKeyPair);
            byte[] readerPrivRaw    = getPrivateKeyRaw(readerKeyPair);

            Log.d(TAG, "Reader pub (= issuer CA pub): " + Hex.toHexString(readerPubUncomp));

            // ------------------------------------------------------------------
            // 2. Build reader_group_identifier: first 16 bytes of SHA-256(reader_pub)
            //    Since reader key = issuer CA key, this is the same regardless
            //    of whether cert or no-cert mode is used.
            // ------------------------------------------------------------------
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] readerPubHash   = sha256.digest(readerPubUncomp);
            byte[] readerGroupId   = Arrays.copyOfRange(readerPubHash, 0, 16);

            // ------------------------------------------------------------------
            // 4. reader_group_sub_identifier: 16 random bytes
            // ------------------------------------------------------------------
            byte[] readerGroupSubId = new byte[16];
            new SecureRandom().nextBytes(readerGroupSubId);

            // ------------------------------------------------------------------
            // 5. reader_identifier = reader_group_identifier || reader_group_sub_identifier
            // ------------------------------------------------------------------
            byte[] readerId = new byte[32];
            System.arraycopy(readerGroupId,   0, readerId, 0,  16);
            System.arraycopy(readerGroupSubId, 0, readerId, 16, 16);

            // ------------------------------------------------------------------
            // 6. Build the profile0000 compressed reader certificate
            // ------------------------------------------------------------------
            byte[] serialNumber = new byte[4];
            new SecureRandom().nextBytes(serialNumber);

            // authorityKeyId = SHA-1 of the signing key's public key.
            // Since self-signed, this is SHA-1 of the reader's own public key.
            // Per §13.3 and RFC 5280 §4.2.1.1.
            byte[] authorityKeyId = computeAuthorityKeyId(readerPubUncomp);

            // Dates — UTCTime format: YYMMDDHHMMSSZ
            SimpleDateFormat utcFmt = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US);
            utcFmt.setTimeZone(TimeZone.getTimeZone("UTC"));
            Date now   = new Date();
            Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            cal.setTime(now);
            cal.add(Calendar.YEAR, 1);
            Date oneYearLater = cal.getTime();
            byte[] notBefore = utcFmt.format(now).getBytes("ASCII");
            byte[] notAfter  = utcFmt.format(oneYearLater).getBytes("ASCII");

            // Subject: "ELATEC-Reader" as UTF-8 bytes
            byte[] subject = "ELATEC-Reader".getBytes("UTF-8");

            // publicKey field in profile0000: 0x00 || 0x04 || X(32) || Y(32) = 66 bytes
            // First byte 0x00 = unused bits count for BIT STRING encoding
            byte[] pubKeyField = new byte[66];
            pubKeyField[0] = 0x00;  // unused bits byte
            pubKeyField[1] = 0x04;  // uncompressed marker
            System.arraycopy(readerPubUncomp, 1, pubKeyField, 2, 64); // skip 0x04 prefix

            // ------------------------------------------------------------------
            // Build reference TBS certificate for signing.
            // Per §13.3, the TBS MUST match the reference X.509 template on
            // page 168 — including all three extensions (AKI, BasicConstraints,
            // KeyUsage). The issuer CN in the TBS uses DEFAULT_ISSUER ("issuer")
            // because we omit the issuer field from the compressed cert.
            // ------------------------------------------------------------------
            byte[] tbsDer = buildReferenceTBS(
                    serialNumber,
                    DEFAULT_ISSUER,
                    notBefore,
                    notAfter,
                    subject,
                    pubKeyField,
                    authorityKeyId);

            // ------------------------------------------------------------------
            // Sign TBS with reader's own private key (self-signed cert)
            // ------------------------------------------------------------------
            byte[] sigDer  = signEcdsaSha256(readerKeyPair.getPrivate(), tbsDer);

            // signature field: 0x00 (unused bits) || DER ECDSA-Sig-Value
            byte[] signatureField = new byte[1 + sigDer.length];
            signatureField[0] = 0x00;  // unused bits byte for BIT STRING
            System.arraycopy(sigDer, 0, signatureField, 1, sigDer.length);

            // ------------------------------------------------------------------
            // Build profile0000 compressed certificate (§13.3 ASN.1 schema)
            // ------------------------------------------------------------------
            byte[] readerCertBytes = buildProfile0000(
                    serialNumber,
                    null,           // issuer: null = omit (use default "issuer")
                    notBefore,
                    notAfter,
                    subject,
                    pubKeyField,
                    signatureField);

            Log.d(TAG, "Reader cert (profile0000): " + Hex.toHexString(readerCertBytes));

            // ------------------------------------------------------------------
            // 7. Store everything in SharedPreferences
            // ------------------------------------------------------------------
            SharedPreferences.Editor editor = context
                    .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .edit();

            // Self-signed: issuer CA key = reader key
            editor.putString(KEY_ISSUER_CA_PRIV,  Hex.toHexString(readerPrivRaw));
            editor.putString(KEY_ISSUER_CA_PUB,   Hex.toHexString(readerPubUncomp));
            editor.putString(KEY_READER_PRIV,     Hex.toHexString(readerPrivRaw));
            editor.putString(KEY_READER_ID,       Hex.toHexString(readerId));
            editor.putString(KEY_READER_CERT,     Hex.toHexString(readerCertBytes));
            editor.putString(KEY_READER_GROUP_ID, Hex.toHexString(readerGroupId));
            editor.putBoolean(KEY_PROVISIONED,    true);
            editor.putBoolean(KEY_STRICT_MODE,    false);
            editor.apply();

            String groupIdPreview = Hex.toHexString(readerGroupId).substring(0, 8) + "...";
            return "Provisioned — Reader Group: " + groupIdPreview
                    + "\nReader ID: " + Hex.toHexString(readerId).substring(0, 8) + "..."
                    + "\nCert size: " + readerCertBytes.length + " bytes";
        }
        catch (Exception e)
        {
            Log.e(TAG, "provisionCredential failed", e);
            return null;
        }
    }

    /**
     * Build the JSON export string for the reader.
     *
     * @param context Android context
     * @return JSON string, or null if not provisioned / error
     */
    public static String buildExportJson(Context context)
    {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        if (!prefs.getBoolean(KEY_PROVISIONED, false)) return null;

        try
        {
            JSONObject obj = new JSONObject();
            obj.put("v",               1);
            obj.put("type",            "aliro_reader_config");
            obj.put("readerPrivateKey", prefs.getString(KEY_READER_PRIV,     ""));
            obj.put("readerId",         prefs.getString(KEY_READER_ID,       ""));
            obj.put("readerCert",       prefs.getString(KEY_READER_CERT,     ""));
            obj.put("issuerPubKey",     prefs.getString(KEY_ISSUER_CA_PUB,   ""));
            obj.put("readerGroupId",    prefs.getString(KEY_READER_GROUP_ID, ""));
            return obj.toString();
        }
        catch (Exception e)
        {
            Log.e(TAG, "buildExportJson failed", e);
            return null;
        }
    }

    /**
     * Returns true if the credential has been provisioned.
     */
    public static boolean isProvisioned(Context context)
    {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getBoolean(KEY_PROVISIONED, false);
    }

    /**
     * Returns true if strict mode is enabled (reject unauthorized readers).
     */
    public static boolean isStrictMode(Context context)
    {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getBoolean(KEY_STRICT_MODE, false);
    }

    /**
     * Set strict mode on or off.
     */
    public static void setStrictMode(Context context, boolean enabled)
    {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(KEY_STRICT_MODE, enabled)
                .apply();
    }

    /**
     * Override the authorized Reader Group ID for test harness testing.
     * Allows a credential to accept AUTH0 from a test harness reader
     * without re-provisioning the entire credential.
     *
     * @param groupIdHex 32-char hex (16 bytes) Reader Group Identifier
     */
    public static void setAuthorizedReaderGroupId(Context context, String groupIdHex)
    {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_READER_GROUP_ID, groupIdHex.toLowerCase(java.util.Locale.US))
                .apply();
    }

    /**
     * Override the Issuer CA public key for test harness testing.
     *
     * @param issuerPubHex 130-char hex (65 bytes, uncompressed EC P-256)
     */
    public static void setIssuerCAPubKey(Context context, String issuerPubHex)
    {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_ISSUER_CA_PUB, issuerPubHex.toLowerCase(java.util.Locale.US))
                .apply();
    }

    /** Get the authorized Reader Group ID as a hex string, or empty if not set. */
    public static String getAuthorizedReaderGroupIdHex(Context context)
    {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_READER_GROUP_ID, "");
    }

    /** Get the Issuer CA public key as a hex string, or empty if not set. */
    public static String getIssuerCAPubKeyHex(Context context)
    {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_ISSUER_CA_PUB, "");
    }

    /** Set the test harness reader public key for AUTH1 signature verification. */
    public static void setTestHarnessReaderPubKey(Context context, String pubKeyHex)
    {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_READER_PUB_KEY, pubKeyHex.toLowerCase(java.util.Locale.US))
                .apply();
    }

    /** Get the test harness reader public key hex, or empty if not set. */
    public static String getTestHarnessReaderPubKeyHex(Context context)
    {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_READER_PUB_KEY, "");
    }

    /** Get the test harness reader public key as 65-byte array, or null. */
    public static byte[] getTestHarnessReaderPubKey(Context context)
    {
        String hex = getTestHarnessReaderPubKeyHex(context);
        if (hex == null || hex.length() != 130) return null;
        return Hex.decode(hex);
    }

    /**
     * Returns the stored Issuer CA public key (65 bytes uncompressed), or null.
     */
    public static byte[] getIssuerCAPubKey(Context context)
    {
        String hex = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_ISSUER_CA_PUB, "");
        if (hex.isEmpty()) return null;
        try { return Hex.decode(hex); }
        catch (Exception e) { return null; }
    }

    /**
     * Returns the 16-byte authorized reader group ID, or null.
     */
    public static byte[] getAuthorizedReaderGroupId(Context context)
    {
        String hex = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_READER_GROUP_ID, "");
        if (hex.isEmpty()) return null;
        try { return Hex.decode(hex); }
        catch (Exception e) { return null; }
    }

    /**
     * Clears all provisioning data.
     */
    public static void clearProvisioning(Context context)
    {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .apply();
    }

    /**
     * Returns a one-line status summary for display in the UI.
     */
    public static String getStatusSummary(Context context)
    {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        if (!prefs.getBoolean(KEY_PROVISIONED, false))
        {
            return "Not provisioned";
        }
        String groupIdHex = prefs.getString(KEY_READER_GROUP_ID, "");
        String preview = groupIdHex.length() >= 8
                ? groupIdHex.substring(0, 8) + "..."
                : groupIdHex;
        return "Provisioned — Reader Group: " + preview;
    }

    // =========================================================================
    // Reader-side import helper
    // =========================================================================

    /**
     * Parses the JSON reader config exported by this manager and stores the
     * reader private key, reader ID, reader certificate, and issuer public key
     * in the reader's activity default SharedPreferences (same as AliroPreferences).
     *
     * Called by the reader app's AliroConfigFragment when the user scans the QR.
     *
     * @param context Android context (from reader app)
     * @param json    JSON string from the QR code
     * @return Summary string on success, null on failure
     */
    public static String importReaderConfig(Context context, String json)
    {
        try
        {
            JSONObject obj = new JSONObject(json);
            if (obj.optInt("v", 0) != 1 ||
                !"aliro_reader_config".equals(obj.optString("type", "")))
            {
                Log.e(TAG, "importReaderConfig: invalid JSON type or version");
                return null;
            }

            String readerPrivKey   = obj.getString("readerPrivateKey").toLowerCase(Locale.US);
            String readerId        = obj.getString("readerId").toLowerCase(Locale.US);
            String readerCert      = obj.getString("readerCert").toLowerCase(Locale.US);
            String issuerPubKey    = obj.getString("issuerPubKey").toLowerCase(Locale.US);
            String readerGroupId   = obj.getString("readerGroupId").toLowerCase(Locale.US);

            // Validate lengths
            if (readerPrivKey.length() != 64) return null;
            if (readerId.length()     != 64) return null;
            if (issuerPubKey.length() != 130) return null;

            // Store in reader's default SharedPreferences
            context
                    .getSharedPreferences("MainActivity", Context.MODE_PRIVATE)
                    .edit()
                    .putString("aliro_reader_private_key",    readerPrivKey)
                    .putString("aliro_reader_id",             readerId)
                    .putString("aliro_reader_issuer_public_key", issuerPubKey)
                    .putString("aliro_reader_certificate",    readerCert)
                    .apply();

            return "Imported reader config\n"
                    + "Reader ID: " + readerId.substring(0, 8) + "...\n"
                    + "Group ID:  " + readerGroupId.substring(0, 8) + "...\n"
                    + "Cert:      " + (readerCert.length() / 2) + " bytes";
        }
        catch (Exception e)
        {
            Log.e(TAG, "importReaderConfig failed", e);
            return null;
        }
    }

    // =========================================================================
    // Certificate verification (for strict mode)
    // =========================================================================

    /**
     * Verify a profile0000 compressed certificate against a known Issuer CA public key.
     *
     * Per Aliro §13.3, the Profile0000 structure is:
     *
     *   SEQUENCE {                         -- Profile0000 (outer)
     *     OCTET STRING (2 bytes: 0x0000)   -- profile identifier
     *     SEQUENCE {                       -- Profile0000Data (inner)
     *       [0] serialNumber  OPTIONAL
     *       [1] issuer        OPTIONAL
     *       [2] notBefore     OPTIONAL
     *       [3] notAfter      OPTIONAL
     *       [4] subject       OPTIONAL
     *       [5] publicKey     (mandatory)
     *       [6] signature     (mandatory)
     *     }
     *   }
     *
     * We extract fields from the inner SEQUENCE, reconstruct the reference TBS
     * using the spec template (§13.3 page 168), and verify the ECDSA-SHA256 signature.
     *
     * @param certBytes    raw profile0000 DER bytes
     * @param issuerPubKey 65-byte uncompressed issuer CA public key
     * @return true if signature is valid
     */
    public static boolean verifyProfile0000Cert(byte[] certBytes, byte[] issuerPubKey)
    {
        try
        {
            // Parse the outer SEQUENCE
            org.bouncycastle.asn1.ASN1InputStream asn1in =
                    new org.bouncycastle.asn1.ASN1InputStream(certBytes);
            ASN1Sequence outerSeq = (ASN1Sequence) asn1in.readObject();
            asn1in.close();

            if (outerSeq.size() < 2)
            {
                Log.w(TAG, "verifyProfile0000Cert: outer SEQUENCE has fewer than 2 elements");
                return false;
            }

            // Element 0: profile OCTET STRING — must be 0x0000
            byte[] profileId;
            try {
                profileId = org.bouncycastle.asn1.ASN1OctetString.getInstance(
                        outerSeq.getObjectAt(0)).getOctets();
            } catch (Exception e) {
                Log.w(TAG, "verifyProfile0000Cert: first element is not OCTET STRING: " + e);
                return false;
            }
            if (profileId.length != 2 || profileId[0] != 0x00 || profileId[1] != 0x00)
            {
                Log.w(TAG, "verifyProfile0000Cert: invalid profile ID: " + Hex.toHexString(profileId));
                return false;
            }

            // Element 1: Profile0000Data SEQUENCE
            ASN1Sequence dataSeq;
            try {
                dataSeq = ASN1Sequence.getInstance(outerSeq.getObjectAt(1));
            } catch (Exception e) {
                Log.w(TAG, "verifyProfile0000Cert: second element is not SEQUENCE: " + e);
                return false;
            }

            // Extract fields from the inner SEQUENCE using implicit context tags [0]..[6]
            byte[] serialNumber = DEFAULT_SERIAL;
            byte[] issuer       = DEFAULT_ISSUER;
            byte[] notBefore    = DEFAULT_NOT_BEFORE;
            byte[] notAfter     = DEFAULT_NOT_AFTER;
            byte[] subject      = DEFAULT_SUBJECT;
            byte[] publicKey    = null;
            byte[] sigField     = null;

            Log.d(TAG, "verifyProfile0000Cert: parsing " + dataSeq.size() + " data elements");
            for (int idx = 0; idx < dataSeq.size(); idx++)
            {
                org.bouncycastle.asn1.ASN1Encodable el = dataSeq.getObjectAt(idx);
                if (el instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject tagged = (ASN1TaggedObject) el;
                    int tagNo = tagged.getTagNo();
                    byte[] octets;
                    try {
                        octets = org.bouncycastle.asn1.ASN1OctetString.getInstance(
                                tagged, false).getOctets();
                    } catch (Exception e) {
                        // Fallback: get the raw encoded content
                        octets = tagged.getBaseObject().toASN1Primitive().getEncoded();
                    }
                    Log.d(TAG, "  tag[" + tagNo + "] = " + octets.length + " bytes");
                    switch (tagNo)
                    {
                        case 0: serialNumber = octets; break;
                        case 1: issuer       = octets; break;
                        case 2: notBefore    = octets; break;
                        case 3: notAfter     = octets; break;
                        case 4: subject      = octets; break;
                        case 5: publicKey    = octets; break;
                        case 6: sigField     = octets; break;
                    }
                }
            }

            if (publicKey == null || sigField == null)
            {
                Log.w(TAG, "verifyProfile0000Cert: missing publicKey (" + (publicKey != null)
                        + ") or signature (" + (sigField != null) + "), elements=" + dataSeq.size());
                return false;
            }

            // sigField = 0x00 || DER-ECDSA-signature
            byte[] sigDer;
            if (sigField.length > 1 && sigField[0] == 0x00)
                sigDer = Arrays.copyOfRange(sigField, 1, sigField.length);
            else
                sigDer = sigField; // try raw

            // Reconstruct the X.509 TBS certificate from the profile0000 fields
            // (same template used during signing in buildReferenceTBS)
            byte[] authorityKeyId = computeAuthorityKeyId(issuerPubKey);
            byte[] tbsDer = buildReferenceTBS(serialNumber, issuer, notBefore,
                    notAfter, subject, publicKey, authorityKeyId);

            // Verify ECDSA-SHA256
            PublicKey issuerPub = decodeUncompressedPublicKey(issuerPubKey);
            if (issuerPub == null) return false;

            Signature sig = Signature.getInstance("SHA256withECDSA",
                    new BouncyCastleProvider());
            sig.initVerify(issuerPub);
            sig.update(tbsDer);
            boolean valid = sig.verify(sigDer);
            Log.d(TAG, "verifyProfile0000Cert: signature valid = " + valid);
            return valid;
        }
        catch (Exception e)
        {
            Log.e(TAG, "verifyProfile0000Cert failed", e);
            return false;
        }
    }

    // =========================================================================
    // Private helpers: certificate building
    // =========================================================================

    /**
     * Build the Aliro profile0000 compressed certificate per §13.3 ASN.1 schema.
     *
     * Correct structure (two nested SEQUENCEs):
     *
     *   SEQUENCE {                                -- Profile0000 (outer)
     *     OCTET STRING { 0x00, 0x00 }             -- profile (raw tag 0x04)
     *     SEQUENCE {                              -- Profile0000Data (inner)
     *       [0] IMPLICIT OCTET STRING serial      -- tag 0x80 (if non-default)
     *       [1] IMPLICIT OCTET STRING issuer      -- tag 0x81 (if non-default)
     *       [2] IMPLICIT OCTET STRING notBefore   -- tag 0x82 (if non-default)
     *       [3] IMPLICIT OCTET STRING notAfter    -- tag 0x83 (if non-default)
     *       [4] IMPLICIT OCTET STRING subject     -- tag 0x84 (if non-default)
     *       [5] IMPLICIT OCTET STRING publicKey   -- tag 0x85 (mandatory)
     *       [6] IMPLICIT OCTET STRING signature   -- tag 0x86 (mandatory)
     *     }
     *   }
     *
     * Fields that match their default value (§13.3 page 167) are omitted.
     * The issuer parameter may be null to indicate "use default" (omit from cert).
     *
     * NOTE: We use manual DER encoding rather than BouncyCastle DERTaggedObject
     * to guarantee correct tag bytes (0x80-0x86). BouncyCastle's implicit tagging
     * can produce incorrect tags on some Android versions.
     */
    private static byte[] buildProfile0000(
            byte[] serialNumber,
            byte[] issuer,          // null = omit (use default "issuer")
            byte[] notBefore,
            byte[] notAfter,
            byte[] subject,
            byte[] publicKey,       // 66 bytes: 0x00 || 0x04 || X || Y
            byte[] signature) throws Exception
    {
        ByteArrayOutputStream dataStream = new ByteArrayOutputStream();

        // [0] serialNumber — omit if matches default
        if (serialNumber != null && !Arrays.equals(serialNumber, DEFAULT_SERIAL))
        {
            writeDerImplicitTag(dataStream, 0, serialNumber);
        }

        // [1] issuer — omit if null or matches default
        if (issuer != null && !Arrays.equals(issuer, DEFAULT_ISSUER))
        {
            writeDerImplicitTag(dataStream, 1, issuer);
        }

        // [2] notBefore — omit if matches default
        if (notBefore != null && !Arrays.equals(notBefore, DEFAULT_NOT_BEFORE))
        {
            writeDerImplicitTag(dataStream, 2, notBefore);
        }

        // [3] notAfter — omit if matches default
        if (notAfter != null && !Arrays.equals(notAfter, DEFAULT_NOT_AFTER))
        {
            writeDerImplicitTag(dataStream, 3, notAfter);
        }

        // [4] subject — omit if matches default
        if (subject != null && !Arrays.equals(subject, DEFAULT_SUBJECT))
        {
            writeDerImplicitTag(dataStream, 4, subject);
        }

        // [5] publicKey — mandatory
        writeDerImplicitTag(dataStream, 5, publicKey);

        // [6] signature — mandatory
        writeDerImplicitTag(dataStream, 6, signature);

        byte[] dataContent = dataStream.toByteArray();

        // Build inner SEQUENCE (Profile0000Data): tag 0x30 + length + content
        ByteArrayOutputStream innerSeqStream = new ByteArrayOutputStream();
        innerSeqStream.write(0x30);
        writeDerLength(innerSeqStream, dataContent.length);
        innerSeqStream.write(dataContent);
        byte[] innerSeq = innerSeqStream.toByteArray();

        // Build profile OCTET STRING: tag 0x04 + length 0x02 + { 0x00, 0x00 }
        byte[] profileOctetString = new byte[] { 0x04, 0x02, 0x00, 0x00 };

        // Build outer SEQUENCE (Profile0000): tag 0x30 + length + (profile + data)
        int outerContentLen = profileOctetString.length + innerSeq.length;
        ByteArrayOutputStream outerStream = new ByteArrayOutputStream();
        outerStream.write(0x30);
        writeDerLength(outerStream, outerContentLen);
        outerStream.write(profileOctetString);
        outerStream.write(innerSeq);

        return outerStream.toByteArray();
    }

    /**
     * Write a context-specific implicit tagged value: tag byte 0x80|tagNum, then DER length, then value.
     */
    private static void writeDerImplicitTag(ByteArrayOutputStream out, int tagNum, byte[] value)
            throws Exception
    {
        out.write(0x80 | tagNum);  // context-specific, primitive
        writeDerLength(out, value.length);
        out.write(value);
    }

    /**
     * Write a DER length encoding to the stream.
     */
    private static void writeDerLength(ByteArrayOutputStream out, int length) throws Exception
    {
        if (length < 0x80)
        {
            out.write(length);
        }
        else if (length < 0x100)
        {
            out.write(0x81);
            out.write(length);
        }
        else
        {
            out.write(0x82);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        }
    }

    /**
     * Build the reference X.509 TBS certificate used for signature computation.
     *
     * This method constructs the TBS to exactly match the reference X.509
     * template from Aliro §13.3 page 168. The harness decompresses a
     * profile0000 cert by inserting fields into this same template, so the
     * TBS we sign MUST be byte-for-byte identical to what the harness
     * reconstructs.
     *
     * The reference template includes THREE extensions (all required by §13.2):
     *   1. Authority Key Identifier (2.5.29.35) — non-critical
     *   2. Basic Constraints (2.5.29.19) — critical, CA:FALSE
     *   3. Key Usage (2.5.29.15) — critical, digitalSignature only
     */
    private static byte[] buildReferenceTBS(
            byte[] serialNumber,
            byte[] issuerCN,        // UTF-8 bytes for issuer Common Name
            byte[] notBefore,       // UTCTime string bytes (e.g. "260417000000Z")
            byte[] notAfter,        // UTCTime string bytes
            byte[] subjectCN,       // UTF-8 bytes for subject Common Name
            byte[] publicKey,       // 66-byte profile0000 format: 00 04 X Y
            byte[] authorityKeyId)  // 20-byte SHA-1 of issuer CA public key
            throws Exception
    {
        // OID byte values
        byte[] oidEcdsaSha256 = Hex.decode("2a8648ce3d040302");
        byte[] oidEcPubKey    = Hex.decode("2a8648ce3d0201");
        byte[] oidSecp256r1   = Hex.decode("2a8648ce3d030107");
        byte[] oidCN          = Hex.decode("550403");
        byte[] oidAKI         = Hex.decode("551d23");
        byte[] oidBasicConst  = Hex.decode("551d13");
        byte[] oidKeyUsage    = Hex.decode("551d0f");

        ByteArrayOutputStream tbs = new ByteArrayOutputStream();

        // Version [0] EXPLICIT INTEGER 2 (v3)
        byte[] versionInt = derInteger(new byte[] { 0x02 });
        byte[] version = derExplicitTag(0, versionInt);

        // SerialNumber INTEGER (positive BigInteger)
        byte[] serialInt = derInteger(serialNumber);

        // Signature AlgorithmIdentifier: SEQUENCE { OID ecdsa-with-SHA256 }
        byte[] sigAlg = derSequence(derOid(oidEcdsaSha256));

        // Issuer: SEQUENCE { SET { SEQUENCE { OID(CN), UTF8String(issuerCN) } } }
        byte[] issuerRdn = derSequence(derOid(oidCN), derUtf8String(issuerCN));
        byte[] issuerSet = derSet(issuerRdn);
        byte[] issuerName = derSequence(issuerSet);

        // Validity: SEQUENCE { UTCTime(notBefore), UTCTime(notAfter) }
        byte[] validity = derSequence(derUtcTime(notBefore), derUtcTime(notAfter));

        // Subject: SEQUENCE { SET { SEQUENCE { OID(CN), UTF8String(subjectCN) } } }
        byte[] subjectRdn = derSequence(derOid(oidCN), derUtf8String(subjectCN));
        byte[] subjectSet = derSet(subjectRdn);
        byte[] subjectName = derSequence(subjectSet);

        // SubjectPublicKeyInfo: SEQUENCE { AlgorithmId, BIT STRING }
        // publicKey = [00 04 X Y] (66 bytes) — includes unused-bits byte
        byte[] spkiAlg = derSequence(derOid(oidEcPubKey), derOid(oidSecp256r1));
        byte[] spkiBitString = derBitString(publicKey);
        byte[] spki = derSequence(spkiAlg, spkiBitString);

        // Extensions [3] EXPLICIT SEQUENCE { ext1, ext2, ext3 }

        // Extension 1: Authority Key Identifier (non-critical)
        //   SEQUENCE { OID(2.5.29.35), OCTET STRING { SEQUENCE { [0] keyIdentifier } } }
        byte[] akiImplicit = derImplicitTag(0, authorityKeyId);
        byte[] akiValue = derSequence(akiImplicit);
        byte[] akiExt = derSequence(derOid(oidAKI), derOctetString(akiValue));

        // Extension 2: Basic Constraints (critical, CA:FALSE)
        //   SEQUENCE { OID(2.5.29.19), BOOLEAN TRUE, OCTET STRING { SEQUENCE {} } }
        byte[] bcValue = derSequence();  // empty SEQUENCE = CA:FALSE
        byte[] bcExt = derSequence(derOid(oidBasicConst), derBoolean(true), derOctetString(bcValue));

        // Extension 3: Key Usage (critical, digitalSignature)
        //   SEQUENCE { OID(2.5.29.15), BOOLEAN TRUE, OCTET STRING { BIT STRING { 07 80 } } }
        byte[] kuBitString = new byte[] { 0x03, 0x02, 0x07, (byte)0x80 };
        byte[] kuExt = derSequence(derOid(oidKeyUsage), derBoolean(true), derOctetString(kuBitString));

        byte[] extList = derSequence(akiExt, bcExt, kuExt);
        byte[] extensions = derExplicitTag(3, extList);

        // Assemble TBS SEQUENCE
        byte[] tbsContent = concat(version, serialInt, sigAlg, issuerName, validity,
                subjectName, spki, extensions);
        return derSequence(tbsContent);
    }

    /**
     * Compute the Authority Key Identifier as SHA-1 of the uncompressed public key
     * (65 bytes: 04 || X || Y). Per RFC 5280 §4.2.1.1 and Aliro §13.3.
     */
    private static byte[] computeAuthorityKeyId(byte[] issuerPubKeyUncompressed) throws Exception
    {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        return sha1.digest(issuerPubKeyUncompressed);
    }

    // =========================================================================
    // Private helpers: manual DER encoding
    // =========================================================================
    // We use manual encoding to guarantee correct tag bytes, avoiding
    // BouncyCastle DERTaggedObject quirks on different Android versions.

    private static byte[] derSequence(byte[]... contents) throws Exception
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] c : contents) out.write(c);
        byte[] content = out.toByteArray();
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x30);
        writeDerLength(result, content.length);
        result.write(content);
        return result.toByteArray();
    }

    private static byte[] derSet(byte[]... contents) throws Exception
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] c : contents) out.write(c);
        byte[] content = out.toByteArray();
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x31);
        writeDerLength(result, content.length);
        result.write(content);
        return result.toByteArray();
    }

    private static byte[] derInteger(byte[] value) throws Exception
    {
        // Ensure positive: if high bit set, prepend 0x00
        byte[] encoded = value;
        if (value.length > 0 && (value[0] & 0x80) != 0)
        {
            encoded = new byte[value.length + 1];
            System.arraycopy(value, 0, encoded, 1, value.length);
        }
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x02);
        writeDerLength(result, encoded.length);
        result.write(encoded);
        return result.toByteArray();
    }

    private static byte[] derOid(byte[] oidBytes) throws Exception
    {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x06);
        writeDerLength(result, oidBytes.length);
        result.write(oidBytes);
        return result.toByteArray();
    }

    private static byte[] derOctetString(byte[] value) throws Exception
    {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x04);
        writeDerLength(result, value.length);
        result.write(value);
        return result.toByteArray();
    }

    private static byte[] derBitString(byte[] value) throws Exception
    {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x03);
        writeDerLength(result, value.length);
        result.write(value);
        return result.toByteArray();
    }

    private static byte[] derUtf8String(byte[] value) throws Exception
    {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x0C);
        writeDerLength(result, value.length);
        result.write(value);
        return result.toByteArray();
    }

    private static byte[] derUtcTime(byte[] value) throws Exception
    {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x17);
        writeDerLength(result, value.length);
        result.write(value);
        return result.toByteArray();
    }

    private static byte[] derBoolean(boolean value) throws Exception
    {
        return new byte[] { 0x01, 0x01, value ? (byte)0xFF : (byte)0x00 };
    }

    private static byte[] derExplicitTag(int tagNum, byte[] content) throws Exception
    {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0xA0 | tagNum);  // context-specific, constructed
        writeDerLength(result, content.length);
        result.write(content);
        return result.toByteArray();
    }

    private static byte[] derImplicitTag(int tagNum, byte[] value) throws Exception
    {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(0x80 | tagNum);  // context-specific, primitive
        writeDerLength(result, value.length);
        result.write(value);
        return result.toByteArray();
    }

    private static byte[] concat(byte[]... arrays) throws Exception
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] a : arrays) out.write(a);
        return out.toByteArray();
    }

    // =========================================================================
    // Private helpers: key generation / encoding
    // =========================================================================

    /** Generate a fresh P-256 keypair using BouncyCastle. */
    private static KeyPair generateP256KeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC",
                new BouncyCastleProvider());
        kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return kpg.generateKeyPair();
    }

    /** Extract the 65-byte uncompressed public key: 0x04 || X(32) || Y(32). */
    private static byte[] getUncompressedPublicKey(KeyPair kp)
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

    /** Extract the raw 32-byte private scalar from a P-256 key pair. */
    private static byte[] getPrivateKeyRaw(KeyPair kp) throws Exception
    {
        // BouncyCastle ECPrivateKey exposes getD() directly
        if (kp.getPrivate() instanceof org.bouncycastle.jce.interfaces.ECPrivateKey)
        {
            org.bouncycastle.jce.interfaces.ECPrivateKey bcPriv =
                    (org.bouncycastle.jce.interfaces.ECPrivateKey) kp.getPrivate();
            return toBytes32(bcPriv.getD());
        }
        // Fallback: parse PKCS#8 encoding
        byte[] encoded = kp.getPrivate().getEncoded();
        // PKCS#8 for EC: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { ECPrivateKey } }
        // ECPrivateKey ::= SEQUENCE { version INTEGER, privateKey OCTET STRING, ... }
        org.bouncycastle.asn1.ASN1InputStream asn1in =
                new org.bouncycastle.asn1.ASN1InputStream(encoded);
        ASN1Sequence pkcs8 = (ASN1Sequence) asn1in.readObject();
        asn1in.close();
        // Element 2 is the OCTET STRING wrapping the ECPrivateKey
        byte[] ecPrivDer = org.bouncycastle.asn1.ASN1OctetString.getInstance(
                pkcs8.getObjectAt(2)).getOctets();
        org.bouncycastle.asn1.ASN1InputStream asn1in2 =
                new org.bouncycastle.asn1.ASN1InputStream(ecPrivDer);
        ASN1Sequence ecPrivSeq = (ASN1Sequence) asn1in2.readObject();
        asn1in2.close();
        byte[] privOctets = org.bouncycastle.asn1.ASN1OctetString.getInstance(
                ecPrivSeq.getObjectAt(1)).getOctets();
        return toBytes32(new BigInteger(1, privOctets));
    }

    /** Sign data with ECDSA-SHA256 using BouncyCastle, returns DER-encoded signature. */
    private static byte[] signEcdsaSha256(PrivateKey privateKey, byte[] data) throws Exception
    {
        Signature sig = Signature.getInstance("SHA256withECDSA",
                new BouncyCastleProvider());
        sig.initSign(privateKey, new SecureRandom());
        sig.update(data);
        return sig.sign();
    }

    /**
     * Decode a 65-byte uncompressed EC public key (04 || X || Y) into a
     * Java PublicKey object using BouncyCastle.
     */
    static PublicKey decodeUncompressedPublicKey(byte[] uncompressed) throws Exception
    {
        if (uncompressed == null || uncompressed.length != 65 || uncompressed[0] != 0x04)
            return null;

        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec =
                org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1");
        org.bouncycastle.math.ec.ECPoint point = spec.getCurve().decodePoint(uncompressed);
        org.bouncycastle.jce.spec.ECPublicKeySpec pubSpec =
                new org.bouncycastle.jce.spec.ECPublicKeySpec(point, spec);
        KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        return kf.generatePublic(pubSpec);
    }

    /** Convert a BigInteger to a fixed 32-byte big-endian array (zero-padded). */
    private static byte[] toBytes32(BigInteger n)
    {
        byte[] raw = n.toByteArray();
        byte[] out = new byte[32];
        if (raw.length <= 32)
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        else
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        return out;
    }
}
