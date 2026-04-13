package com.psia.pkoc.core;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
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
import java.security.spec.PKCS8EncodedKeySpec;
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
            // 1. Generate Issuer CA keypair (P-256)
            // ------------------------------------------------------------------
            KeyPair issuerCAKeyPair = generateP256KeyPair();
            byte[] issuerCAPubUncompressed = getUncompressedPublicKey(issuerCAKeyPair);
            byte[] issuerCAPrivRaw         = getPrivateKeyRaw(issuerCAKeyPair);

            Log.d(TAG, "Issuer CA pub: " + Hex.toHexString(issuerCAPubUncompressed));

            // ------------------------------------------------------------------
            // 2. Generate reader keypair (P-256)
            // ------------------------------------------------------------------
            KeyPair readerKeyPair   = generateP256KeyPair();
            byte[] readerPubUncomp  = getUncompressedPublicKey(readerKeyPair);
            byte[] readerPrivRaw    = getPrivateKeyRaw(readerKeyPair);

            // ------------------------------------------------------------------
            // 3. Build reader_group_identifier: first 16 bytes of SHA-256(issuerCA_pub_uncompressed)
            // ------------------------------------------------------------------
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] issuerPubHash   = sha256.digest(issuerCAPubUncompressed);
            byte[] readerGroupId   = Arrays.copyOfRange(issuerPubHash, 0, 16);

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

            // authorityKeyId = SHA-1 of issuer CA public key (uncompressed)
            byte[] authorityKeyId = computeAuthorityKeyId(issuerCAPubUncompressed);

            // Dates
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
            byte[] pubKeyField = new byte[66];
            pubKeyField[0] = 0x00;  // unused bits byte
            pubKeyField[1] = 0x04;  // uncompressed marker
            System.arraycopy(readerPubUncomp, 1, pubKeyField, 2, 64); // skip 0x04 prefix

            // ------------------------------------------------------------------
            // Build reference TBS certificate for signing
            // ------------------------------------------------------------------
            // Use the default issuer name ("issuer") because the profile0000
            // compressed format does not store the issuer field — the verifier
            // will reconstruct the TBS with DEFAULT_ISSUER, so we must sign
            // with the same value to get a matching hash.
            byte[] tbsDer = buildReferenceTBS(
                    serialNumber,
                    DEFAULT_ISSUER,
                    notBefore,
                    notAfter,
                    subject,
                    pubKeyField,
                    authorityKeyId);

            // ------------------------------------------------------------------
            // Sign TBS with issuer CA private key using ECDSA-SHA256
            // ------------------------------------------------------------------
            byte[] tbsHash = sha256.digest(tbsDer);
            byte[] sigDer  = signEcdsaSha256(issuerCAKeyPair.getPrivate(), tbsDer);

            // signature field: 0x00 (unused bits) || DER ECDSA-Sig-Value
            byte[] signatureField = new byte[1 + sigDer.length];
            signatureField[0] = 0x00;  // unused bits byte for BIT STRING
            System.arraycopy(sigDer, 0, signatureField, 1, sigDer.length);

            // ------------------------------------------------------------------
            // Build profile0000 certificate
            // ------------------------------------------------------------------
            byte[] readerCertBytes = buildProfile0000(
                    serialNumber,
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

            editor.putString(KEY_ISSUER_CA_PRIV,  Hex.toHexString(issuerCAPrivRaw));
            editor.putString(KEY_ISSUER_CA_PUB,   Hex.toHexString(issuerCAPubUncompressed));
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
            context.getSharedPreferences("MainActivity", Context.MODE_PRIVATE)
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
     * The profile0000 structure (§13.3) contains:
     *   SEQUENCE {
     *     profileId       [0] OCTET STRING (2 bytes: 00 00)
     *     serialNumber    [1] OCTET STRING
     *     notBefore       [2] UTCTime
     *     notAfter        [3] UTCTime
     *     subject         [4] UTF8String bytes
     *     publicKey       [5] BIT STRING (66 bytes: 00 04 X Y)
     *     signature       [6] BIT STRING (00 || DER ECDSA)
     *   }
     *
     * We reconstruct the TBS from fields [0]..[5] and verify the signature in field [6].
     *
     * @param certBytes    raw profile0000 DER bytes
     * @param issuerPubKey 65-byte uncompressed issuer CA public key
     * @return true if signature is valid
     */
    public static boolean verifyProfile0000Cert(byte[] certBytes, byte[] issuerPubKey)
    {
        try
        {
            // Parse the profile0000 SEQUENCE
            org.bouncycastle.asn1.ASN1InputStream asn1in =
                    new org.bouncycastle.asn1.ASN1InputStream(certBytes);
            org.bouncycastle.asn1.ASN1Sequence outerSeq =
                    (org.bouncycastle.asn1.ASN1Sequence) asn1in.readObject();
            asn1in.close();

            // The profile0000 is built as a flat SEQUENCE with IMPLICIT TAGGED
            // elements [0]..[6].  Walk all elements and extract by tag number.
            // BouncyCastle may parse implicit tags as ASN1TaggedObject (base class)
            // rather than DERTaggedObject, so check the base class.

            byte[] serialNumber = DEFAULT_SERIAL;
            byte[] issuer       = DEFAULT_ISSUER;
            byte[] notBefore    = DEFAULT_NOT_BEFORE;
            byte[] notAfter     = DEFAULT_NOT_AFTER;
            byte[] subject      = DEFAULT_SUBJECT;
            byte[] publicKey    = null;
            byte[] sigField     = null;

            Log.d(TAG, "verifyProfile0000Cert: parsing " + outerSeq.size() + " elements");
            for (int idx = 0; idx < outerSeq.size(); idx++)
            {
                org.bouncycastle.asn1.ASN1Encodable el = outerSeq.getObjectAt(idx);
                // Check for tagged object (implicit tags)
                if (el instanceof org.bouncycastle.asn1.ASN1TaggedObject)
                {
                    org.bouncycastle.asn1.ASN1TaggedObject tagged =
                            (org.bouncycastle.asn1.ASN1TaggedObject) el;
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
                        case 0: /* profileId — skip */ break;
                        case 1: serialNumber = octets; break;
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
                        + ") or signature (" + (sigField != null) + "), elements=" + outerSeq.size());
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
     * Build the Aliro profile0000 compressed certificate (§13.3).
     *
     * ASN.1 schema:
     *   Profile0000Certificate ::= SEQUENCE {
     *     profileId             [0] IMPLICIT OCTET STRING,   -- 00 00
     *     serialNumber          [1] IMPLICIT OCTET STRING,
     *     notBefore             [2] IMPLICIT UTCTime,
     *     notAfter              [3] IMPLICIT UTCTime,
     *     subject               [4] IMPLICIT OCTET STRING,   -- UTF-8 bytes
     *     publicKey             [5] IMPLICIT BIT STRING,     -- 00 04 X Y
     *     signature             [6] IMPLICIT BIT STRING      -- 00 || DER ECDSA
     *   }
     */
    private static byte[] buildProfile0000(
            byte[] serialNumber,
            byte[] notBefore,
            byte[] notAfter,
            byte[] subject,
            byte[] publicKey,
            byte[] signature) throws Exception
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        // [0] profileId OCTET STRING
        v.add(new DERTaggedObject(false, 0, new DEROctetString(PROFILE_ID)));
        // [1] serialNumber OCTET STRING
        v.add(new DERTaggedObject(false, 1, new DEROctetString(serialNumber)));
        // [2] notBefore UTCTime (raw bytes stored as OCTET STRING in compressed form)
        v.add(new DERTaggedObject(false, 2, new DEROctetString(notBefore)));
        // [3] notAfter UTCTime
        v.add(new DERTaggedObject(false, 3, new DEROctetString(notAfter)));
        // [4] subject UTF8String bytes as OCTET STRING
        v.add(new DERTaggedObject(false, 4, new DEROctetString(subject)));
        // [5] publicKey BIT STRING
        v.add(new DERTaggedObject(false, 5, new DEROctetString(publicKey)));
        // [6] signature BIT STRING
        v.add(new DERTaggedObject(false, 6, new DEROctetString(signature)));

        return new DERSequence(v).getEncoded();
    }

    /**
     * Build the reference X.509 TBS certificate used for signature computation.
     *
     * Follows the template from Aliro §13.3 / page 168:
     *   TBSCertificate ::= SEQUENCE {
     *     version              [0] EXPLICIT INTEGER (v3 = 2)
     *     serialNumber             INTEGER
     *     signature                AlgorithmIdentifier (ecdsa-with-SHA256)
     *     issuer                   Name (CN=issuer)
     *     validity                 Validity { notBefore, notAfter }
     *     subject                  Name (CN=subject)
     *     subjectPublicKeyInfo     SubjectPublicKeyInfo (EC P-256, uncompressed)
     *     extensions          [3] EXPLICIT Extensions { authorityKeyIdentifier }
     *   }
     */
    private static byte[] buildReferenceTBS(
            byte[] serialNumber,
            byte[] issuer,
            byte[] notBefore,
            byte[] notAfter,
            byte[] subject,
            byte[] publicKey,   // 66-byte profile0000 format: 00 04 X Y
            byte[] authorityKeyId) throws Exception
    {
        // Algorithm identifier: ecdsa-with-SHA256
        AlgorithmIdentifier ecdsaSha256AlgId = new AlgorithmIdentifier(
                new ASN1ObjectIdentifier(OID_ECDSA_SHA256));

        // Algorithm identifier for the subject public key: id-ecPublicKey + secp256r1
        AlgorithmIdentifier ecAlgId = new AlgorithmIdentifier(
                new ASN1ObjectIdentifier(OID_EC_PUBLIC_KEY),
                new ASN1ObjectIdentifier(OID_SECP256R1));

        // SubjectPublicKeyInfo: extract actual EC point from publicKey (skip 00 prefix byte)
        // publicKey[0] = 0x00 (unused bits), publicKey[1..65] = 04 X Y
        byte[] ecPoint = Arrays.copyOfRange(publicKey, 1, publicKey.length); // 65 bytes: 04 X Y
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(ecAlgId,
                new DERBitString(ecPoint).getBytes());

        // Version [0] EXPLICIT v3 (value 2)
        DERTaggedObject version = new DERTaggedObject(true, 0, new ASN1Integer(2));

        // SerialNumber INTEGER (treat bytes as positive BigInteger)
        ASN1Integer serialInt = new ASN1Integer(new BigInteger(1, serialNumber));

        // Issuer Name: CN=<issuer string>
        X500Name issuerName = new X500Name("CN=" + new String(issuer, "UTF-8"));

        // Validity
        ASN1EncodableVector validityVec = new ASN1EncodableVector();
        validityVec.add(new DERUTCTime(new String(notBefore, "ASCII")));
        validityVec.add(new DERUTCTime(new String(notAfter, "ASCII")));
        DERSequence validity = new DERSequence(validityVec);

        // Subject Name: CN=<subject string>
        X500Name subjectName = new X500Name("CN=" + new String(subject, "UTF-8"));

        // SubjectPublicKeyInfo (rebuild properly)
        byte[] ecPointFull = Arrays.copyOfRange(publicKey, 1, publicKey.length); // 04 X Y
        SubjectPublicKeyInfo spkiProper = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(
                        new ASN1ObjectIdentifier(OID_EC_PUBLIC_KEY),
                        new ASN1ObjectIdentifier(OID_SECP256R1)),
                ecPointFull);

        // Authority Key Identifier extension
        // Extension OID: 2.5.29.35, value: SEQUENCE { [0] keyIdentifier }
        ASN1EncodableVector akiContentVec = new ASN1EncodableVector();
        akiContentVec.add(new DERTaggedObject(false, 0, new DEROctetString(authorityKeyId)));
        byte[] akiContent = new DERSequence(akiContentVec).getEncoded();

        ASN1EncodableVector akiExtVec = new ASN1EncodableVector();
        akiExtVec.add(new ASN1ObjectIdentifier("2.5.29.35"));
        akiExtVec.add(new DEROctetString(akiContent));
        DERSequence akiExt = new DERSequence(akiExtVec);

        ASN1EncodableVector extListVec = new ASN1EncodableVector();
        extListVec.add(akiExt);
        DERSequence extList = new DERSequence(extListVec);
        DERTaggedObject extensions = new DERTaggedObject(true, 3, extList);

        // Build TBSCertificate SEQUENCE
        ASN1EncodableVector tbsVec = new ASN1EncodableVector();
        tbsVec.add(version);
        tbsVec.add(serialInt);
        tbsVec.add(ecdsaSha256AlgId);
        tbsVec.add(issuerName);
        tbsVec.add(validity);
        tbsVec.add(subjectName);
        tbsVec.add(spkiProper);
        tbsVec.add(extensions);

        return new DERSequence(tbsVec).getEncoded();
    }

    /**
     * Compute the Authority Key Identifier as SHA-1 of the uncompressed public key (65 bytes).
     * Per RFC 5280 §4.2.1.1 and Aliro §13.3 recommendation.
     */
    private static byte[] computeAuthorityKeyId(byte[] issuerPubKeyUncompressed) throws Exception
    {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        return sha1.digest(issuerPubKeyUncompressed);
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
        org.bouncycastle.asn1.ASN1Sequence pkcs8 =
                (org.bouncycastle.asn1.ASN1Sequence) asn1in.readObject();
        asn1in.close();
        // Element 2 is the OCTET STRING wrapping the ECPrivateKey
        byte[] ecPrivDer = org.bouncycastle.asn1.ASN1OctetString.getInstance(
                pkcs8.getObjectAt(2)).getOctets();
        org.bouncycastle.asn1.ASN1InputStream asn1in2 =
                new org.bouncycastle.asn1.ASN1InputStream(ecPrivDer);
        org.bouncycastle.asn1.ASN1Sequence ecPrivSeq =
                (org.bouncycastle.asn1.ASN1Sequence) asn1in2.readObject();
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
