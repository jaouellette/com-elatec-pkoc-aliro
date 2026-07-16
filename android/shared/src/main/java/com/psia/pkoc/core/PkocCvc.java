package com.psia.pkoc.core;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * PKOC-CVC — PKOC Card Verifiable Certificate (PKOC Core Specification 2.0.1, §5).
 *
 * <p>The baseline card-bound attestation certificate used by the NFC Validated
 * Mode. It is a self-descriptive BER-TLV structure (ISO/IEC 7816-4/-6) that binds
 * a subject public key to an issuer, and MAY carry extension credentials.</p>
 *
 * <pre>
 *  7F21  CV Certificate
 *    7F4E  Certificate Body                      &lt;-- the exact bytes that are signed
 *      5F29  Certificate Profile Identifier (0)
 *      42    Issuer Identification Reference (IIR, 16 chars)
 *      7F49  Public Key   { 06 curve-OID, 86 point (EC) | 06,81,82 (RSA) | 06,86 (ML-DSA) }
 *      5F20  Subject Identification Reference (16 chars)
 *      5F25  Certificate Effective Date (YYMMDD, unpacked BCD)
 *      5F24  Certificate Expiration Date (YYMMDD, unpacked BCD)
 *      65    Certificate Extension Data (optional) { 73 { 06 OID, 53 value } ... }
 *    5F37  Signature (raw, over the complete 7F4E body TLV)
 * </pre>
 *
 * <p>This class parses the complete container, exposes every field, verifies the
 * issuer signature (delegated to {@link IssuerKey} so the algorithm follows the
 * issuer key), and can build/sign a certificate with an EC P-256 issuer key for
 * demo/self-test use. It is transport-independent and reuses the existing
 * {@link EcKeyUtil}/{@link CryptoProvider} primitives.</p>
 */
public final class PkocCvc
{
    // --- ASN.1 / interindustry tags (Core §5.2) ---
    public static final int TAG_OID              = 0x06;
    public static final int TAG_IIR              = 0x42;   // Issuer Identification Reference
    public static final int TAG_DISCRETIONARY    = 0x53;   // value
    public static final int TAG_EXTENSION_DATA   = 0x65;   // Certificate Extension Data
    public static final int TAG_DDT              = 0x73;   // Discretionary Data Template
    public static final int TAG_EC_POINT         = 0x86;   // Public Point (EC) / ML-DSA public key
    public static final int TAG_RSA_MODULUS      = 0x81;
    public static final int TAG_RSA_EXPONENT     = 0x82;
    public static final int TAG_SUBJECT_REF      = 0x5F20;
    public static final int TAG_VALID_TO         = 0x5F24;
    public static final int TAG_VALID_FROM       = 0x5F25;
    public static final int TAG_PROFILE_ID       = 0x5F29;
    public static final int TAG_SIGNATURE        = 0x5F37;
    public static final int TAG_CV_CERTIFICATE   = 0x7F21;
    public static final int TAG_PUBLIC_KEY       = 0x7F49;
    public static final int TAG_CERT_BODY        = 0x7F4E;

    public static final int PROFILE_V1 = 0;

    // --- Algorithm OIDs (Core §5.5) ---
    public static final byte[] OID_EC_P256 = hex("2A8648CE3D030107");           // 1.2.840.10045.3.1.7
    public static final byte[] OID_RSA     = hex("2A864886F70D010101");         // 1.2.840.113549.1.1.1

    // --- Extension credential OIDs (Core §5.7), PEN 59685 ---
    public static final byte[] OID_EXT_KEYID     = hex("2B0601040183D2250701"); // .7.1
    public static final byte[] OID_EXT_UUID      = hex("2B0601040183D2250801"); // .8.1
    public static final byte[] OID_EXT_4BYTEUID  = hex("2B0601040183D2250802"); // .8.2
    public static final byte[] OID_EXT_7BYTEUID  = hex("2B0601040183D2250803"); // .8.3
    public static final byte[] OID_EXT_10BYTEUID = hex("2B0601040183D2250805"); // .8.5
    public static final byte[] OID_EXT_BINARYID  = hex("2B0601040183D2250807"); // .8.7
    public static final byte[] OID_EXT_CARDINFO  = hex("2B0601040183D2250808"); // .8.8
    public static final byte[] OID_EXT_PKOC      = hex("2B0601040183D2250809"); // .8.9
    public static final byte[] OID_EXT_CARDTYPE  = hex("2B0601040183D2250810"); // .8.16

    /** A parsed extension: PSIA OID (tag 06) + value (tag 53). */
    public static final class Extension
    {
        public final byte[] oid;
        public final byte[] value;
        Extension(byte[] oid, byte[] value) { this.oid = oid; this.value = value; }
    }

    private final byte[] raw;                 // full 7F21 TLV
    private final byte[] certificateBody;     // full 7F4E TLV (the signed region)
    private final byte[] signature;           // 5F37 value

    private final int profileId;
    private final String iir;                 // 16 chars
    private final byte[] publicKeyOid;        // 06 within 7F49
    private final byte[] ecPoint;             // 86 within 7F49 (EC/ML-DSA), else null
    private final byte[] rsaModulus;          // 81 within 7F49 (RSA), else null
    private final byte[] rsaExponent;         // 82 within 7F49 (RSA), else null
    private final String subjectRef;          // 16 chars
    private final int validFromYyyymmdd;
    private final int validToYyyymmdd;
    private final List<Extension> extensions;

    private PkocCvc(byte[] raw, byte[] body, byte[] signature, int profileId, String iir,
                    byte[] pkOid, byte[] ecPoint, byte[] rsaMod, byte[] rsaExp,
                    String subjectRef, int validFrom, int validTo, List<Extension> extensions)
    {
        this.raw = raw;
        this.certificateBody = body;
        this.signature = signature;
        this.profileId = profileId;
        this.iir = iir;
        this.publicKeyOid = pkOid;
        this.ecPoint = ecPoint;
        this.rsaModulus = rsaMod;
        this.rsaExponent = rsaExp;
        this.subjectRef = subjectRef;
        this.validFromYyyymmdd = validFrom;
        this.validToYyyymmdd = validTo;
        this.extensions = extensions;
    }

    // ====================================================================
    // Parsing
    // ====================================================================

    /**
     * Parse a PKOC-CVC from the value of tag {@code 7F21} (either the full TLV
     * beginning {@code 7F 21 …}, or just the inner value — both are accepted).
     *
     * @return the parsed certificate, or {@code null} if malformed
     */
    @Nullable
    public static PkocCvc parse(byte[] input)
    {
        if (input == null || input.length < 4)
        {
            return null;
        }
        try
        {
            byte[] cvcTlv;
            int[] hdr = readTag(input, 0);
            if (hdr != null && hdr[0] == TAG_CV_CERTIFICATE)
            {
                cvcTlv = input;
            }
            else
            {
                // Assume the caller passed just the 7F21 value; wrap it.
                cvcTlv = tlv(TAG_CV_CERTIFICATE, input);
            }

            Tlv cv = readOne(cvcTlv, 0);
            if (cv == null || cv.tag != TAG_CV_CERTIFICATE)
            {
                return null;
            }

            // Children of 7F21: 7F4E (body) then 5F37 (signature).
            byte[] bodyTlv = null;
            byte[] sig = null;
            int cursor = 0;
            while (cursor < cv.value.length)
            {
                Tlv child = readOne(cv.value, cursor);
                if (child == null) return null;
                if (child.tag == TAG_CERT_BODY)
                {
                    bodyTlv = Arrays.copyOfRange(cv.value, cursor, child.end); // include tag+len (signed region)
                }
                else if (child.tag == TAG_SIGNATURE)
                {
                    sig = child.value;
                }
                cursor = child.end;
            }
            if (bodyTlv == null || sig == null)
            {
                return null;
            }

            Tlv body = readOne(bodyTlv, 0);
            if (body == null || body.tag != TAG_CERT_BODY) return null;

            int profileId = -1;
            String iir = null, subjectRef = null;
            byte[] pkOid = null, ecPoint = null, rsaMod = null, rsaExp = null;
            int validFrom = -1, validTo = -1;
            List<Extension> exts = new ArrayList<>();

            int p = 0;
            while (p < body.value.length)
            {
                Tlv f = readOne(body.value, p);
                if (f == null) return null;
                switch (f.tag)
                {
                    case TAG_PROFILE_ID:
                        profileId = (f.value.length == 1) ? (f.value[0] & 0xFF) : -1;
                        break;
                    case TAG_IIR:
                        iir = new String(f.value, java.nio.charset.StandardCharsets.US_ASCII);
                        break;
                    case TAG_PUBLIC_KEY:
                    {
                        int q = 0;
                        while (q < f.value.length)
                        {
                            Tlv k = readOne(f.value, q);
                            if (k == null) return null;
                            if (k.tag == TAG_OID) pkOid = k.value;
                            else if (k.tag == TAG_EC_POINT) ecPoint = k.value;
                            else if (k.tag == TAG_RSA_MODULUS) rsaMod = k.value;
                            else if (k.tag == TAG_RSA_EXPONENT) rsaExp = k.value;
                            q = k.end;
                        }
                        break;
                    }
                    case TAG_SUBJECT_REF:
                        subjectRef = new String(f.value, java.nio.charset.StandardCharsets.US_ASCII);
                        break;
                    case TAG_VALID_FROM:
                        validFrom = decodeBcdDate(f.value);
                        break;
                    case TAG_VALID_TO:
                        validTo = decodeBcdDate(f.value);
                        break;
                    case TAG_EXTENSION_DATA:
                    {
                        int q = 0;
                        while (q < f.value.length)
                        {
                            Tlv ddt = readOne(f.value, q);
                            if (ddt == null) return null;
                            if (ddt.tag == TAG_DDT)
                            {
                                byte[] oid = null, val = null;
                                int r = 0;
                                while (r < ddt.value.length)
                                {
                                    Tlv e = readOne(ddt.value, r);
                                    if (e == null) return null;
                                    if (e.tag == TAG_OID) oid = e.value;
                                    else if (e.tag == TAG_DISCRETIONARY) val = e.value;
                                    r = e.end;
                                }
                                if (oid != null && val != null) exts.add(new Extension(oid, val));
                            }
                            q = ddt.end;
                        }
                        break;
                    }
                    default:
                        break; // ignore unrecognized body fields
                }
                p = f.end;
            }

            return new PkocCvc(cvcTlv.clone(), bodyTlv, sig, profileId, iir, pkOid,
                    ecPoint, rsaMod, rsaExp, subjectRef, validFrom, validTo, exts);
        }
        catch (Exception e)
        {
            return null;
        }
    }

    // ====================================================================
    // Build + sign (EC P-256 issuer) — for demo card provisioning / self-tests
    // ====================================================================

    /**
     * Build and sign a Profile v1 PKOC-CVC with an EC P-256 subject key and an
     * EC P-256 (ES256) issuer key.
     *
     * @param iir16                16-char Issuer Identification Reference
     * @param subjectPublicPoint65 subject public key, uncompressed {@code 04||X||Y}
     * @param subjectRef16         16-char Subject Identification Reference
     * @param validFromYyyymmdd    effective date, e.g. 20260709
     * @param validToYyyymmdd      expiration date, e.g. 20300709
     * @param extensions           extension credentials to embed (may be empty/null)
     * @param issuerPrivateKey     EC P-256 issuer private key (signs the body)
     * @return a signed {@code PkocCvc}, or {@code null} on failure
     */
    @Nullable
    public static PkocCvc buildAndSignEcP256(
            @NonNull String iir16,
            @NonNull byte[] subjectPublicPoint65,
            @NonNull String subjectRef16,
            int validFromYyyymmdd,
            int validToYyyymmdd,
            @Nullable List<Extension> extensions,
            @NonNull PrivateKey issuerPrivateKey)
    {
        if (iir16.length() != 16 || subjectRef16.length() != 16 || subjectPublicPoint65.length != 65)
        {
            return null;
        }
        try
        {
            byte[] pubKey = tlv(TAG_PUBLIC_KEY,
                    concat(tlv(TAG_OID, OID_EC_P256), tlv(TAG_EC_POINT, subjectPublicPoint65)));

            byte[] extBytes = new byte[0];
            if (extensions != null && !extensions.isEmpty())
            {
                byte[] ddts = new byte[0];
                for (Extension e : extensions)
                {
                    byte[] ddt = tlv(TAG_DDT, concat(tlv(TAG_OID, e.oid), tlv(TAG_DISCRETIONARY, e.value)));
                    ddts = concat(ddts, ddt);
                }
                extBytes = tlv(TAG_EXTENSION_DATA, ddts);
            }

            byte[] bodyInner = concat(
                    tlv(TAG_PROFILE_ID, new byte[] { (byte) PROFILE_V1 }),
                    tlv(TAG_IIR, iir16.getBytes(java.nio.charset.StandardCharsets.US_ASCII)),
                    pubKey,
                    tlv(TAG_SUBJECT_REF, subjectRef16.getBytes(java.nio.charset.StandardCharsets.US_ASCII)),
                    tlv(TAG_VALID_FROM, encodeBcdDate(validFromYyyymmdd)),
                    tlv(TAG_VALID_TO, encodeBcdDate(validToYyyymmdd)),
                    extBytes);

            byte[] body = tlv(TAG_CERT_BODY, bodyInner);

            byte[] sig = EcKeyUtil.signRaw(issuerPrivateKey, body); // ES256 over the full 7F4E TLV
            if (sig == null || sig.length != 64)
            {
                return null;
            }

            byte[] cvc = tlv(TAG_CV_CERTIFICATE, concat(body, tlv(TAG_SIGNATURE, sig)));
            return parse(cvc);
        }
        catch (Exception e)
        {
            return null;
        }
    }

    // ====================================================================
    // Accessors
    // ====================================================================

    public byte[] encode()               { return raw.clone(); }
    public byte[] getCertificateBody()   { return certificateBody.clone(); }  // the signed region
    public byte[] getSignature()         { return signature.clone(); }
    public int getProfileId()            { return profileId; }
    public String getIir()               { return iir; }
    public String getSubjectRef()        { return subjectRef; }
    public int getValidFromYyyymmdd()    { return validFromYyyymmdd; }
    public int getValidToYyyymmdd()      { return validToYyyymmdd; }
    public byte[] getPublicKeyOid()      { return publicKeyOid == null ? null : publicKeyOid.clone(); }
    public List<Extension> getExtensions() { return extensions; }

    public boolean isEcKey()  { return publicKeyOid != null && Arrays.equals(publicKeyOid, OID_EC_P256) && ecPoint != null; }
    public boolean isRsaKey() { return publicKeyOid != null && Arrays.equals(publicKeyOid, OID_RSA) && rsaModulus != null; }

    /** The subject EC public key as an uncompressed {@code 04||X||Y} point, or {@code null}. */
    @Nullable
    public byte[] getSubjectEcPublicKeyUncompressed()
    {
        return (ecPoint != null && ecPoint.length == 65) ? ecPoint.clone() : null;
    }

    public byte[] getRsaModulus()  { return rsaModulus == null ? null : rsaModulus.clone(); }
    public byte[] getRsaExponent() { return rsaExponent == null ? null : rsaExponent.clone(); }

    /** Return the value of the first extension matching the given PSIA OID, or {@code null}. */
    @Nullable
    public byte[] getExtension(byte[] oid)
    {
        for (Extension e : extensions)
        {
            if (Arrays.equals(e.oid, oid))
            {
                return e.value.clone();
            }
        }
        return null;
    }

    /**
     * Derive the PKOC Credential (Core §4) from the subject key for Reader-to-PACS
     * output. Uses V1 (P-256 X coordinate) for EC keys.
     */
    @Nullable
    public byte[] derivePkocCredential()
    {
        byte[] pt = getSubjectEcPublicKeyUncompressed();
        return pt == null ? null : PkocCredentialDerivation.deriveCredentialV1(pt);
    }

    // ====================================================================
    // IIR + validity checks
    // ====================================================================

    /** Whether the IIR is a well-formed 16-char A–Z / 0–9 string (Core §5.4). */
    public boolean isIirWellFormed()
    {
        if (iir == null || iir.length() != 16) return false;
        for (int i = 0; i < 16; i++)
        {
            char c = iir.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
            if (!ok) return false;
        }
        return true;
    }

    /**
     * Whether {@code nowYyyymmdd} falls within [effective, expiration] (Core §5.6).
     * Dates are integers such as 20260709.
     */
    public boolean isWithinValidity(int nowYyyymmdd)
    {
        if (validFromYyyymmdd <= 0 || validToYyyymmdd <= 0) return false;
        return nowYyyymmdd >= validFromYyyymmdd && nowYyyymmdd <= validToYyyymmdd;
    }

    // ====================================================================
    // BER-TLV helpers
    // ====================================================================

    private static final class Tlv
    {
        final int tag;
        final byte[] value;
        final int end;   // index in the parent buffer just past this TLV
        Tlv(int tag, byte[] value, int end) { this.tag = tag; this.value = value; this.end = end; }
    }

    /** Read a single TLV starting at {@code off}. */
    @Nullable
    private static Tlv readOne(byte[] b, int off)
    {
        int[] t = readTag(b, off);
        if (t == null) return null;
        int tag = t[0];
        int i = t[1];
        int[] l = readLen(b, i);
        if (l == null) return null;
        int len = l[0];
        int valStart = l[1];
        if (valStart + len > b.length) return null;
        byte[] value = Arrays.copyOfRange(b, valStart, valStart + len);
        return new Tlv(tag, value, valStart + len);
    }

    /** @return {@code [tag, nextIndex]} or {@code null}. Handles 1- and 2-byte tags. */
    @Nullable
    private static int[] readTag(byte[] b, int off)
    {
        if (off >= b.length) return null;
        int first = b[off] & 0xFF;
        if ((first & 0x1F) == 0x1F)
        {
            if (off + 1 >= b.length) return null;
            int tag = (first << 8) | (b[off + 1] & 0xFF);
            return new int[] { tag, off + 2 };
        }
        return new int[] { first, off + 1 };
    }

    /** @return {@code [length, valueStartIndex]} or {@code null}. Handles 1/2/3-byte DER lengths. */
    @Nullable
    private static int[] readLen(byte[] b, int off)
    {
        if (off >= b.length) return null;
        int first = b[off] & 0xFF;
        if (first < 0x80) return new int[] { first, off + 1 };
        if (first == 0x81)
        {
            if (off + 1 >= b.length) return null;
            return new int[] { b[off + 1] & 0xFF, off + 2 };
        }
        if (first == 0x82)
        {
            if (off + 2 >= b.length) return null;
            return new int[] { ((b[off + 1] & 0xFF) << 8) | (b[off + 2] & 0xFF), off + 3 };
        }
        return null;
    }

    private static byte[] tlv(int tag, byte[] value)
    {
        byte[] tagBytes = (tag > 0xFF)
                ? new byte[] { (byte) (tag >> 8), (byte) tag }
                : new byte[] { (byte) tag };
        byte[] lenBytes;
        int n = value.length;
        if (n < 0x80)       lenBytes = new byte[] { (byte) n };
        else if (n < 0x100) lenBytes = new byte[] { (byte) 0x81, (byte) n };
        else                lenBytes = new byte[] { (byte) 0x82, (byte) (n >> 8), (byte) n };
        return concat(tagBytes, lenBytes, value);
    }

    private static int decodeBcdDate(byte[] six)
    {
        if (six == null || six.length != 6) return -1;
        int yy = six[0] * 10 + six[1];
        int mm = six[2] * 10 + six[3];
        int dd = six[4] * 10 + six[5];
        return (2000 + yy) * 10000 + mm * 100 + dd;
    }

    private static byte[] encodeBcdDate(int yyyymmdd)
    {
        int yy = (yyyymmdd / 10000) % 100;
        int mm = (yyyymmdd / 100) % 100;
        int dd = yyyymmdd % 100;
        return new byte[] {
                (byte) (yy / 10), (byte) (yy % 10),
                (byte) (mm / 10), (byte) (mm % 10),
                (byte) (dd / 10), (byte) (dd % 10)
        };
    }

    private static byte[] concat(byte[]... parts)
    {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, pos, p.length); pos += p.length; }
        return out;
    }

    private static byte[] hex(String s)
    {
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
        {
            out[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return out;
    }
}
