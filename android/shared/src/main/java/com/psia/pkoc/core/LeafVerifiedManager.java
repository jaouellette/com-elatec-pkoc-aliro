package com.psia.pkoc.core;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

/**
 * LEAF Verified — shared utility class.
 *
 * Manages provisioning (credential side), certificate construction/parsing,
 * and all cryptographic operations needed for the LEAF Open ID (Path 1)
 * protocol on Android.
 *
 * All crypto uses BouncyCastle with {@code new BouncyCastleProvider()} — NOT the string "BC".
 */
public final class LeafVerifiedManager
{
    private static final String TAG = "LeafVerifiedManager";

    // -----------------------------------------------------------------------
    // Protocol constants
    // -----------------------------------------------------------------------

    /** LEAF Open App AID — D2 76 00 00 85 01 01 */
    public static final byte[] LEAF_OPEN_APP_AID = {
        (byte)0xD2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01
    };

    /** Certificate EF file identifier — 00 01 */
    public static final byte[] LEAF_CERT_FILE_ID = { 0x00, 0x01 };

    /** SharedPreferences file name for all LEAF data (avoids Aliro namespace collisions). */
    public static final String PREFS_NAME = "LeafVerified";

    // SharedPreferences keys
    private static final String KEY_OPEN_ID          = "openId";
    private static final String KEY_CERT_DER_B64     = "certDerB64";
    private static final String KEY_CRED_PRIV_HEX    = "credPrivHex";
    private static final String KEY_ROOT_CA_PUB_HEX  = "rootCaPubHex";
    private static final String KEY_ROOT_CA_PRIV_HEX = "rootCaPrivHex";

    // OID for ECDSA with SHA-256
    private static final ASN1ObjectIdentifier OID_ECDSA_SHA256 =
            new ASN1ObjectIdentifier("1.2.840.10045.4.3.2");
    // OID for EC public key
    private static final ASN1ObjectIdentifier OID_EC_PUBLIC_KEY =
            new ASN1ObjectIdentifier("1.2.840.10045.2.1");
    // OID for secp256r1 / P-256
    private static final ASN1ObjectIdentifier OID_P256 =
            new ASN1ObjectIdentifier("1.2.840.10045.3.1.7");

    private LeafVerifiedManager() {}

    // -----------------------------------------------------------------------
    // Provisioning (credential side)
    // -----------------------------------------------------------------------

    /**
     * Generate all LEAF credential material and store in SharedPreferences.
     *
     * Creates:
     *   - LEAF Root CA keypair (P-256) — acts as the Root CA for testing
     *   - Credential keypair (P-256) — the credential's identity
     *   - X.509 certificate: Root CA signs the credential's public key
     *   - 12-digit random Open ID embedded in the certificate subject CN
     *
     * @param context Android context
     * @return summary string on success, or null on failure
     */
    public static String provisionLeafCredential(Context context)
    {
        try
        {
            Security.addProvider(new BouncyCastleProvider());

            // Generate Root CA keypair
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            KeyPair rootCAKeyPair = kpg.generateKeyPair();

            // Generate Credential keypair
            KeyPair credKeyPair = kpg.generateKeyPair();

            // Generate 12-digit Open ID
            SecureRandom rng = new SecureRandom();
            long openIdLong = ((rng.nextLong() >>> 1) % 900_000_000_000L) + 100_000_000_000L;
            String openId = String.format(Locale.US, "%012d", openIdLong);

            // Extract credential public key bytes (65-byte uncompressed)
            byte[] credPubKeyBytes = getUncompressedPublicKey(credKeyPair.getPublic());

            // Build X.509 certificate
            byte[] certDER = generateX509Cert(rootCAKeyPair, credPubKeyBytes, openId);
            if (certDER == null)
            {
                Log.e(TAG, "provisionLeafCredential: certificate generation failed");
                return null;
            }

            // Extract raw private key bytes for storage
            byte[] credPrivBytes    = getRawPrivateKeyBytes(credKeyPair.getPrivate());
            byte[] rootCAPubBytes   = getUncompressedPublicKey(rootCAKeyPair.getPublic());
            byte[] rootCAPrivBytes  = getRawPrivateKeyBytes(rootCAKeyPair.getPrivate());

            // Persist everything
            SharedPreferences.Editor ed = context
                    .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .edit();
            ed.putString(KEY_OPEN_ID,          openId);
            ed.putString(KEY_CERT_DER_B64,     Base64.encodeToString(certDER, Base64.DEFAULT));
            ed.putString(KEY_CRED_PRIV_HEX,    Hex.toHexString(credPrivBytes));
            ed.putString(KEY_ROOT_CA_PUB_HEX,  Hex.toHexString(rootCAPubBytes));
            // Root CA private key is NOT persisted — credential never needs it
            // again after cert issuance. Keeping it would compromise the PKI
            // trust model if device storage is accessed.
            ed.remove(KEY_ROOT_CA_PRIV_HEX);
            ed.apply();

            return "LEAF credential provisioned.\n"
                    + "Open ID: " + openId + "\n"
                    + "Cert:    " + certDER.length + " bytes\n"
                    + "Root CA: " + Hex.toHexString(rootCAPubBytes).substring(0, 16) + "...";
        }
        catch (Exception e)
        {
            Log.e(TAG, "provisionLeafCredential failed", e);
            return null;
        }
    }

    /** @return the 12-digit Open ID string, or null if not provisioned. */
    public static String getOpenID(Context context)
    {
        return prefs(context).getString(KEY_OPEN_ID, null);
    }

    /** @return DER-encoded X.509 certificate bytes, or null if not provisioned. */
    public static byte[] getCredentialCertDER(Context context)
    {
        String b64 = prefs(context).getString(KEY_CERT_DER_B64, null);
        if (b64 == null) return null;
        try { return Base64.decode(b64, Base64.DEFAULT); }
        catch (Exception e) { return null; }
    }

    /** @return 32-byte raw credential private key, or null if not provisioned. */
    public static byte[] getCredentialPrivateKey(Context context)
    {
        String hex = prefs(context).getString(KEY_CRED_PRIV_HEX, null);
        if (hex == null || hex.isEmpty()) return null;
        try { return Hex.decode(hex); }
        catch (Exception e) { return null; }
    }

    /** @return 65-byte uncompressed Root CA public key, or null if not provisioned. */
    public static byte[] getRootCAPubKey(Context context)
    {
        String hex = prefs(context).getString(KEY_ROOT_CA_PUB_HEX, null);
        if (hex == null || hex.isEmpty()) return null;
        try { return Hex.decode(hex); }
        catch (Exception e) { return null; }
    }

    /** @return true if credential, cert, and Root CA keys are all present. */
    public static boolean isProvisioned(Context context)
    {
        SharedPreferences p = prefs(context);
        return p.contains(KEY_OPEN_ID)
                && p.contains(KEY_CERT_DER_B64)
                && p.contains(KEY_CRED_PRIV_HEX)
                && p.contains(KEY_ROOT_CA_PUB_HEX);
    }

    /** Remove all LEAF provisioning data. */
    public static void clearProvisioning(Context context)
    {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
               .edit().clear().apply();
    }

    /**
     * Build a JSON export string containing the Root CA public key for reader import.
     * Format: {"v":1,"type":"leaf_reader_config","rootCAPubKey":"04..."}
     */
    public static String buildExportJson(Context context)
    {
        byte[] rootCAPub = getRootCAPubKey(context);
        if (rootCAPub == null) return null;
        return "{\"v\":1,\"type\":\"leaf_reader_config\",\"rootCAPubKey\":\""
                + Hex.toHexString(rootCAPub) + "\"}";
    }

    // -----------------------------------------------------------------------
    // Certificate helpers
    // -----------------------------------------------------------------------

    /**
     * Build a DER-encoded X.509v3 certificate.
     *
     * Subject:  CN=LEAF-<openID>
     * Issuer:   CN=LEAF Root CA
     * Public:   credential's P-256 key (65-byte uncompressed)
     * Signed:   Root CA private key with ECDSA-SHA256
     * Validity: now + 1 year
     *
     * @param issuerKP       Root CA keypair (signs the cert)
     * @param credPubKey     65-byte uncompressed credential public key
     * @param openID         12-digit numeric Open ID string
     * @return DER-encoded certificate bytes, or null on error
     */
    public static byte[] generateX509Cert(KeyPair issuerKP, byte[] credPubKey, String openID)
    {
        try
        {
            Security.addProvider(new BouncyCastleProvider());

            // Subject and Issuer names
            X500Name subject = new X500Name("CN=LEAF-" + openID);
            X500Name issuer  = new X500Name("CN=LEAF Root CA");

            // Validity: now to now+1year
            Date notBefore = new Date();
            Calendar cal = Calendar.getInstance();
            cal.setTime(notBefore);
            cal.add(Calendar.YEAR, 1);
            Date notAfter = cal.getTime();

            // Serial number (random 16-byte)
            SecureRandom rng = new SecureRandom();
            byte[] serialBytes = new byte[16];
            rng.nextBytes(serialBytes);
            BigInteger serial = new BigInteger(1, serialBytes);

            // Build SubjectPublicKeyInfo for P-256 credential key
            SubjectPublicKeyInfo spki = buildP256SubjectPublicKeyInfo(credPubKey);

            // Build TBS certificate
            V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
            tbsGen.setSerialNumber(new ASN1Integer(serial));
            tbsGen.setSignature(new AlgorithmIdentifier(OID_ECDSA_SHA256));
            tbsGen.setIssuer(issuer);
            tbsGen.setStartDate(new Time(notBefore));
            tbsGen.setEndDate(new Time(notAfter));
            tbsGen.setSubject(subject);
            tbsGen.setSubjectPublicKeyInfo(spki);

            // Add BasicConstraints extension (not a CA)
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            extGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

            // Custom extension: embed the Open ID as UTF8String under private arc OID
            // OID 1.3.6.1.4.1.65535.1.1 — used as the LEAF Open ID extension
            ASN1ObjectIdentifier leafOpenIdOid = new ASN1ObjectIdentifier("1.3.6.1.4.1.65535.1.1");
            extGen.addExtension(leafOpenIdOid, false,
                    new DEROctetString(new DERUTF8String(openID).getEncoded()));

            tbsGen.setExtensions(extGen.generate());
            TBSCertificate tbsCert = tbsGen.generateTBSCertificate();

            // Sign TBS with Root CA private key (ECDSA-SHA256)
            byte[] tbsDER = tbsCert.getEncoded();
            Signature sig = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
            sig.initSign(issuerKP.getPrivate());
            sig.update(tbsDER);
            byte[] sigDER = sig.sign(); // DER-encoded ECDSA signature

            // Assemble full certificate: SEQUENCE { tbsCert, algId, sigBitString }
            ASN1EncodableVector certVec = new ASN1EncodableVector();
            certVec.add(tbsCert);
            certVec.add(new AlgorithmIdentifier(OID_ECDSA_SHA256));
            certVec.add(new DERBitString(sigDER));
            DERSequence certSeq = new DERSequence(certVec);
            return certSeq.getEncoded();
        }
        catch (Exception e)
        {
            Log.e(TAG, "generateX509Cert failed", e);
            return null;
        }
    }

    /**
     * Extract the 65-byte uncompressed P-256 public key from a DER-encoded X.509 certificate.
     *
     * @param certDER DER-encoded certificate
     * @return 65-byte uncompressed public key (04 || X || Y), or null on error
     */
    public static byte[] extractPublicKeyFromCert(byte[] certDER)
    {
        try
        {
            ASN1Sequence cert = (ASN1Sequence) ASN1Primitive.fromByteArray(certDER);
            // cert[0] = TBSCertificate
            ASN1Sequence tbs = (ASN1Sequence) cert.getObjectAt(0);
            // Find SubjectPublicKeyInfo — it's after the optional extensions
            // TBSCertificate field order (v3):
            //   [0] version, serialNumber, signature, issuer, validity,
            //       subject, subjectPublicKeyInfo, [3]extensions
            // Field index for spki: version is EXPLICIT [0], serial=0,sig=1,issuer=2,validity=3,subject=4,spki=5
            // If no version tag, serial=0,sig=1,issuer=2,validity=3,subject=4,spki=5
            int spkiIndex = -1;
            for (int i = 0; i < tbs.size(); i++)
            {
                Object obj = tbs.getObjectAt(i);
                if (obj instanceof ASN1Sequence)
                {
                    ASN1Sequence seq = (ASN1Sequence) obj;
                    if (seq.size() == 2)
                    {
                        Object inner = seq.getObjectAt(0);
                        if (inner instanceof ASN1Sequence)
                        {
                            ASN1Sequence algSeq = (ASN1Sequence) inner;
                            if (algSeq.size() >= 1
                                    && algSeq.getObjectAt(0) instanceof ASN1ObjectIdentifier)
                            {
                                ASN1ObjectIdentifier oid =
                                        (ASN1ObjectIdentifier) algSeq.getObjectAt(0);
                                if (OID_EC_PUBLIC_KEY.equals(oid))
                                {
                                    spkiIndex = i;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            if (spkiIndex < 0)
            {
                Log.e(TAG, "extractPublicKeyFromCert: SPKI not found");
                return null;
            }
            ASN1Sequence spki = (ASN1Sequence) tbs.getObjectAt(spkiIndex);
            ASN1BitString pubKeyBits = (ASN1BitString) spki.getObjectAt(1);
            byte[] pubKeyBytes = pubKeyBits.getOctets(); // should be 65 bytes, 04 || X || Y
            if (pubKeyBytes.length == 65 && (pubKeyBytes[0] & 0xFF) == 0x04)
                return pubKeyBytes;
            Log.e(TAG, "extractPublicKeyFromCert: unexpected key format, len=" + pubKeyBytes.length);
            return null;
        }
        catch (Exception e)
        {
            Log.e(TAG, "extractPublicKeyFromCert failed", e);
            return null;
        }
    }

    /**
     * Extract the 12-digit Open ID from the certificate's subject CN field.
     * The CN is expected to be "LEAF-XXXXXXXXXXXX" (LEAF- prefix + 12 digits).
     *
     * @param certDER DER-encoded certificate
     * @return 12-digit Open ID string, or null on error
     */
    public static String extractOpenIDFromCert(byte[] certDER)
    {
        try
        {
            ASN1Sequence cert = (ASN1Sequence) ASN1Primitive.fromByteArray(certDER);
            TBSCertificate tbs = TBSCertificate.getInstance(cert.getObjectAt(0));
            X500Name subject = tbs.getSubject();
            String cn = null;
            // getRDNs returns the RDNs — find CN
            org.bouncycastle.asn1.x500.RDN[] rdns = subject.getRDNs(BCStyle.CN);
            if (rdns != null && rdns.length > 0)
            {
                cn = rdns[0].getFirst().getValue().toString();
            }
            if (cn == null) return null;
            // Strip "LEAF-" prefix
            if (cn.startsWith("LEAF-"))
                return cn.substring(5);
            return cn;
        }
        catch (Exception e)
        {
            Log.e(TAG, "extractOpenIDFromCert failed", e);
            return null;
        }
    }

    /**
     * Extract the ECDSA signature from the certificate as raw 64-byte R||S.
     * The signature field in an X.509 cert is DER-encoded. This method returns
     * the raw (r||s) form (32 bytes each), not DER.
     *
     * @param certDER DER-encoded certificate
     * @return 64-byte R||S signature, or null on error
     */
    public static byte[] extractSignatureFromCert(byte[] certDER)
    {
        try
        {
            ASN1Sequence cert = (ASN1Sequence) ASN1Primitive.fromByteArray(certDER);
            // cert[2] = BIT STRING containing DER-encoded ECDSA signature
            ASN1BitString sigBits = ASN1BitString.getInstance(cert.getObjectAt(2));
            byte[] sigDER = sigBits.getOctets();
            return derSignatureToRawRS(sigDER);
        }
        catch (Exception e)
        {
            Log.e(TAG, "extractSignatureFromCert failed", e);
            return null;
        }
    }

    /**
     * Extract the TBS (To-Be-Signed) portion of a DER-encoded certificate.
     *
     * @param certDER DER-encoded certificate
     * @return DER-encoded TBSCertificate bytes, or null on error
     */
    public static byte[] extractTBSFromCert(byte[] certDER)
    {
        try
        {
            ASN1Sequence cert = (ASN1Sequence) ASN1Primitive.fromByteArray(certDER);
            return cert.getObjectAt(0).toASN1Primitive().getEncoded();
        }
        catch (Exception e)
        {
            Log.e(TAG, "extractTBSFromCert failed", e);
            return null;
        }
    }

    /**
     * Verify the certificate's ECDSA-SHA256 signature against the provided Root CA public key.
     *
     * @param certDER      DER-encoded certificate
     * @param rootCAPubKey 65-byte uncompressed Root CA public key
     * @return true if the certificate signature is valid
     */
    public static boolean verifyCertificate(byte[] certDER, byte[] rootCAPubKey)
    {
        try
        {
            Security.addProvider(new BouncyCastleProvider());

            // Rebuild the Root CA ECPublicKey
            PublicKey rootCAPub = uncompressedBytesToECPublicKey(rootCAPubKey);
            if (rootCAPub == null) return false;

            // Verify using JCA Signature
            Signature verifier = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
            verifier.initVerify(rootCAPub);

            // Feed the TBS bytes
            byte[] tbsBytes = extractTBSFromCert(certDER);
            if (tbsBytes == null) return false;
            verifier.update(tbsBytes);

            // Extract DER signature from cert
            ASN1Sequence cert = (ASN1Sequence) ASN1Primitive.fromByteArray(certDER);
            ASN1BitString sigBits = ASN1BitString.getInstance(cert.getObjectAt(2));
            byte[] sigDER = sigBits.getOctets();

            return verifier.verify(sigDER);
        }
        catch (Exception e)
        {
            Log.e(TAG, "verifyCertificate failed", e);
            return false;
        }
    }

    // -----------------------------------------------------------------------
    // ECDSA signing (credential / HCE side)
    // -----------------------------------------------------------------------

    /**
     * Sign a 32-byte challenge with the credential's private key using ECDSA-SHA256.
     * Returns a DER-encoded ECDSA signature.
     *
     * @param challenge32    32-byte random challenge from the reader
     * @param credPrivKey32  32-byte raw credential private key
     * @return DER-encoded ECDSA signature, or null on error
     */
    public static byte[] signChallenge(byte[] challenge32, byte[] credPrivKey32)
    {
        if (challenge32 == null || challenge32.length != 32)
        {
            Log.e(TAG, "signChallenge: challenge must be exactly 32 bytes, got "
                    + (challenge32 == null ? "null" : String.valueOf(challenge32.length)));
            return null;
        }
        try
        {
            Security.addProvider(new BouncyCastleProvider());
            PrivateKey privKey = rawBytesToECPrivateKey(credPrivKey32);
            if (privKey == null) return null;
            Signature sig = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
            sig.initSign(privKey);
            sig.update(challenge32);
            return sig.sign(); // DER-encoded
        }
        catch (Exception e)
        {
            Log.e(TAG, "signChallenge failed", e);
            return null;
        }
    }

    /**
     * Verify a DER-encoded ECDSA-SHA256 signature against a challenge.
     *
     * @param challenge32  original 32-byte challenge
     * @param sigDER       DER-encoded ECDSA signature from INTERNAL AUTHENTICATE
     * @param pubKey65     65-byte uncompressed credential public key from cert
     * @return true if signature is valid
     */
    public static boolean verifyChallenge(byte[] challenge32, byte[] sigDER, byte[] pubKey65)
    {
        try
        {
            Security.addProvider(new BouncyCastleProvider());
            PublicKey pub = uncompressedBytesToECPublicKey(pubKey65);
            if (pub == null) return false;
            Signature verifier = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
            verifier.initVerify(pub);
            verifier.update(challenge32);
            return verifier.verify(sigDER);
        }
        catch (Exception e)
        {
            Log.e(TAG, "verifyChallenge failed", e);
            return false;
        }
    }

    // -----------------------------------------------------------------------
    // Reader-side Root CA storage
    // -----------------------------------------------------------------------

    /** Preference key for the reader's LEAF Root CA public key (hex). */
    public static final String READER_PREF_ROOT_CA_PUB = "leafRootCaPubHex";

    /** Preference key for LEAF mode enabled flag. */
    public static final String READER_PREF_LEAF_MODE   = "leafModeEnabled";

    /**
     * Store the Root CA public key (imported from credential QR) in the reader's
     * default SharedPreferences.
     *
     * @param context    reader app context
     * @param rootCaHex  130-hex-char (65-byte) uncompressed public key
     */
    public static void setReaderRootCAPubKey(Context context, String rootCaHex)
    {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
               .edit()
               .putString(READER_PREF_ROOT_CA_PUB, rootCaHex)
               .apply();
    }

    /**
     * Get the Root CA public key stored on the reader side (65 bytes),
     * or null if not configured.
     */
    public static byte[] getReaderRootCAPubKey(Context context)
    {
        String hex = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                            .getString(READER_PREF_ROOT_CA_PUB, null);
        if (hex == null || hex.isEmpty()) return null;
        try { return Hex.decode(hex); }
        catch (Exception e) { return null; }
    }

    /**
     * Get the Root CA public key as a hex string from the reader side.
     */
    public static String getReaderRootCAPubKeyHex(Context context)
    {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                      .getString(READER_PREF_ROOT_CA_PUB, null);
    }

    // -----------------------------------------------------------------------
    // Internal cryptographic helpers
    // -----------------------------------------------------------------------

    /**
     * Build a SubjectPublicKeyInfo ASN.1 structure for a P-256 uncompressed public key.
     *
     * @param uncompressedKey 65-byte uncompressed EC point (04 || X || Y)
     */
    private static SubjectPublicKeyInfo buildP256SubjectPublicKeyInfo(byte[] uncompressedKey)
            throws Exception
    {
        AlgorithmIdentifier algId = new AlgorithmIdentifier(OID_EC_PUBLIC_KEY, OID_P256);
        return new SubjectPublicKeyInfo(algId, uncompressedKey);
    }

    /**
     * Convert a raw 32-byte private key scalar to a {@link PrivateKey}.
     *
     * @param rawBytes 32-byte big-endian private key scalar
     */
    public static PrivateKey rawBytesToECPrivateKey(byte[] rawBytes)
    {
        try
        {
            Security.addProvider(new BouncyCastleProvider());
            ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECNamedCurveSpec params = new ECNamedCurveSpec(
                    "secp256r1", spec.getCurve(), spec.getG(), spec.getN(), spec.getH());
            BigInteger d = new BigInteger(1, rawBytes);
            ECPrivateKeySpec keySpec = new ECPrivateKeySpec(d, params);
            KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
            return kf.generatePrivate(keySpec);
        }
        catch (Exception e)
        {
            Log.e(TAG, "rawBytesToECPrivateKey failed", e);
            return null;
        }
    }

    /**
     * Convert a 65-byte uncompressed P-256 public key to a {@link PublicKey}.
     */
    public static PublicKey uncompressedBytesToECPublicKey(byte[] uncompressedKey)
    {
        try
        {
            Security.addProvider(new BouncyCastleProvider());
            ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
            org.bouncycastle.math.ec.ECCurve curve = spec.getCurve();
            ECPoint point = curve.decodePoint(uncompressedKey);
            org.bouncycastle.jce.spec.ECPublicKeySpec pubSpec =
                    new org.bouncycastle.jce.spec.ECPublicKeySpec(point, spec);
            KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
            return kf.generatePublic(pubSpec);
        }
        catch (Exception e)
        {
            Log.e(TAG, "uncompressedBytesToECPublicKey failed", e);
            return null;
        }
    }

    /**
     * Get the 65-byte uncompressed public key from a {@link PublicKey}.
     */
    public static byte[] getUncompressedPublicKey(PublicKey pub)
    {
        try
        {
            ECPublicKey ecPub = (ECPublicKey) pub;
            byte[] x = toBytes32(ecPub.getW().getAffineX());
            byte[] y = toBytes32(ecPub.getW().getAffineY());
            byte[] out = new byte[65];
            out[0] = 0x04;
            System.arraycopy(x, 0, out, 1,  32);
            System.arraycopy(y, 0, out, 33, 32);
            return out;
        }
        catch (Exception e)
        {
            Log.e(TAG, "getUncompressedPublicKey failed", e);
            return null;
        }
    }

    /**
     * Extract the raw 32-byte private key scalar from an ECPrivateKey.
     */
    private static byte[] getRawPrivateKeyBytes(PrivateKey priv)
    {
        ECPrivateKey ecPriv = (ECPrivateKey) priv;
        return toBytes32(ecPriv.getS());
    }

    /**
     * Convert a BigInteger to exactly 32 bytes (big-endian, zero-padded or truncated).
     */
    static byte[] toBytes32(BigInteger n)
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
     * Convert a DER-encoded ECDSA signature to raw 64-byte R||S form.
     * DER format: SEQUENCE { INTEGER r, INTEGER s }
     */
    public static byte[] derSignatureToRawRS(byte[] sigDER)
    {
        try
        {
            ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(sigDER);
            BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
            BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
            byte[] out = new byte[64];
            byte[] rb = toBytes32(r);
            byte[] sb = toBytes32(s);
            System.arraycopy(rb, 0, out, 0,  32);
            System.arraycopy(sb, 0, out, 32, 32);
            return out;
        }
        catch (Exception e)
        {
            Log.e(TAG, "derSignatureToRawRS failed", e);
            return null;
        }
    }

    /**
     * Convert raw 64-byte R||S signature to DER format.
     */
    public static byte[] rawRSToDerSignature(byte[] rawRS)
    {
        try
        {
            byte[] rBytes = new byte[32];
            byte[] sBytes = new byte[32];
            System.arraycopy(rawRS, 0,  rBytes, 0, 32);
            System.arraycopy(rawRS, 32, sBytes, 0, 32);
            BigInteger r = new BigInteger(1, rBytes);
            BigInteger s = new BigInteger(1, sBytes);
            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(new ASN1Integer(r));
            vec.add(new ASN1Integer(s));
            return new DERSequence(vec).getEncoded();
        }
        catch (Exception e)
        {
            Log.e(TAG, "rawRSToDerSignature failed", e);
            return null;
        }
    }

    // -----------------------------------------------------------------------
    // Private helper
    // -----------------------------------------------------------------------

    private static SharedPreferences prefs(Context context)
    {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    // =========================================================================
    // Wiegand 40-bit Output Encoding (per LEAF spec)
    // =========================================================================

    /**
     * Encode a 12-digit Open ID into a 40-bit Wiegand frame per LEAF spec:
     * <ul>
     *   <li>Bit 0: even parity over bits 1–19</li>
     *   <li>Bits 1–38: 38 data bits (Open ID as integer)</li>
     *   <li>Bit 39: odd parity over bits 20–38</li>
     * </ul>
     * This format is identical for both Open ID and Enterprise ID output.
     *
     * @param openId12 exactly 12 decimal digits
     * @return 5-byte (40-bit) array, MSB first
     */
    public static byte[] encodeWiegand40(String openId12)
    {
        long idVal = Long.parseLong(openId12);

        // 38-bit data field supports up to 274,877,906,943 (covers all 12-digit IDs)
        long data38 = idVal & 0x3FFFFFFFFFL;

        // Place 38 data bits in positions 1–38, shifted left by 1 for bit 39
        long frame = data38 << 1;

        // Even parity (bit 0) over bits 1–19 (upper 19 of 38 data bits)
        long upper19 = (data38 >> 19) & 0x7FFFFL;
        int evenParity = (Long.bitCount(upper19) % 2 == 0) ? 0 : 1;

        // Odd parity (bit 39) over bits 20–38 (lower 19 of 38 data bits)
        long lower19 = data38 & 0x7FFFFL;
        int oddParity = (Long.bitCount(lower19) % 2 == 0) ? 1 : 0;

        // Set parity bits
        frame |= ((long) evenParity << 39);
        frame |= oddParity;

        // Convert to 5 bytes, MSB first
        byte[] result = new byte[5];
        result[0] = (byte) ((frame >> 32) & 0xFF);
        result[1] = (byte) ((frame >> 24) & 0xFF);
        result[2] = (byte) ((frame >> 16) & 0xFF);
        result[3] = (byte) ((frame >> 8) & 0xFF);
        result[4] = (byte) (frame & 0xFF);
        return result;
    }

    /**
     * Format a 40-bit Wiegand frame as a display string showing the binary
     * and hex representation.
     *
     * @param openId12 exactly 12 decimal digits
     * @return formatted string like "0x BA2E... (10111010...)" or null on error
     */
    public static String formatWiegand40Display(String openId12)
    {
        try
        {
            byte[] w = encodeWiegand40(openId12);
            long frame = 0;
            for (int i = 0; i < 5; i++)
                frame = (frame << 8) | (w[i] & 0xFF);

            // Hex representation
            StringBuilder hex = new StringBuilder();
            for (byte b : w) hex.append(String.format("%02X", b));

            // Binary representation (40 bits)
            String bin = String.format("%40s", Long.toBinaryString(frame)).replace(' ', '0');
            // Insert spaces: P DDDDDDDDDDDDDDDDDDD DDDDDDDDDDDDDDDDDDD P
            String formatted = bin.charAt(0) + " "
                    + bin.substring(1, 20) + " "
                    + bin.substring(20, 39) + " "
                    + bin.charAt(39);

            return "0x" + hex + "  (" + formatted + ")";
        }
        catch (Exception e)
        {
            return null;
        }
    }
}
