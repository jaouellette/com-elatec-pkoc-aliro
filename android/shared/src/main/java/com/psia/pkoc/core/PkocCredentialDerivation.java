package com.psia.pkoc.core;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;

/**
 * PKOC Core Specification 2.0.1 — Section 4: PKOC Credentials and Derived Identifiers.
 *
 * <p>Transport-independent derivation of a 32-octet PKOC Credential and the shorter
 * PKOC Derived Identifier from a public key. A given public key yields the same
 * PKOC Credential and the same Derived Identifiers whether presented over BLE, NFC,
 * or any future transport (Core §4).</p>
 *
 * <p>This class is deliberately dependency-light (JCA + java.util.Base64 only) and
 * has no knowledge of any transport. It is additive: it is safe to introduce without
 * affecting the existing PKOC, Aliro, or LEAF Verified code paths, and it becomes the
 * single source of truth for Reader-to-PACS credential output (NFC §3.6) and for the
 * derivation self-tests.</p>
 */
public final class PkocCredentialDerivation
{
    private PkocCredentialDerivation() { }

    /** A PKOC Credential is always 32 octets (Core §4.1). */
    public static final int PKOC_CREDENTIAL_LENGTH = 32;

    /** Standard PKOC Derived Identifier length bounds, in octets (Core §4.1). */
    public static final int DERIVED_ID_MIN_OCTETS = 8;
    public static final int DERIVED_ID_MAX_OCTETS = 31;

    /** Validated PKOC Derived Identifier lower bound (Core §4.6). Lengths 4–7 require
     *  issuer-attested uniqueness scoped to the IIR. */
    public static final int VALIDATED_DERIVED_ID_MIN_OCTETS = 4;

    /** DER-encoded OID arcs (Core §4.2.5). */
    public static final byte[] OID_PKOC_CREDENTIAL =
            hexToBytes("2B0601040183FC2F0C01");           // 1.3.6.1.4.1.65071.12.1
    public static final byte[] OID_PKOC_DERIVED_IDENTIFIER =
            hexToBytes("2B0601040183FC2F0C02");           // 1.3.6.1.4.1.65071.12.2

    // ---------------------------------------------------------------------
    // Credential derivation (Core §4.3 / §4.4)
    // ---------------------------------------------------------------------

    /**
     * PKOC Credential V1 — ECC P-256 (Core §4.3).
     *
     * <p>The credential is the 32-octet X coordinate of the uncompressed SEC1 point.
     * The input MUST be a 65-octet uncompressed point ({@code 0x04 || X || Y});
     * compressed encodings MUST NOT be used for V1.</p>
     *
     * @param uncompressedP256PublicKey 65-byte {@code 0x04 || X(32) || Y(32)} point
     * @return the 32-octet PKOC Credential (the X coordinate)
     */
    public static byte[] deriveCredentialV1(byte[] uncompressedP256PublicKey)
    {
        if (uncompressedP256PublicKey == null || uncompressedP256PublicKey.length != 65
                || (uncompressedP256PublicKey[0] & 0xFF) != 0x04)
        {
            throw new IllegalArgumentException(
                    "PKOC Credential V1 requires a 65-byte uncompressed SEC1 P-256 point (0x04||X||Y).");
        }
        byte[] credential = new byte[PKOC_CREDENTIAL_LENGTH];
        System.arraycopy(uncompressedP256PublicKey, 1, credential, 0, PKOC_CREDENTIAL_LENGTH);
        return credential;
    }

    /**
     * PKOC Credential V2 — hashed public key (Core §4.4).
     *
     * <p>Applies to keys not covered by V1 (ECC curves other than P-256, RSA, etc.).
     * The credential is {@code SHA-256(DER-encoded SubjectPublicKeyInfo)}.</p>
     *
     * <p>Note: a NIST P-256 key MUST be derived with V1 and MUST NOT use V2
     * (Core §4.4), so a given key yields a single canonical credential.</p>
     *
     * @param derSubjectPublicKeyInfo the DER-encoded SPKI bytes of the public key
     * @return the 32-octet PKOC Credential
     */
    public static byte[] deriveCredentialV2(byte[] derSubjectPublicKeyInfo)
    {
        if (derSubjectPublicKeyInfo == null || derSubjectPublicKeyInfo.length == 0)
        {
            throw new IllegalArgumentException("PKOC Credential V2 requires DER-encoded SPKI bytes.");
        }
        return sha256(derSubjectPublicKeyInfo);
    }

    /**
     * PKOC Credential V2 from a {@link PublicKey}. {@link PublicKey#getEncoded()} returns
     * the X.509 SubjectPublicKeyInfo DER encoding, exactly what §4.4 hashes.
     */
    public static byte[] deriveCredentialV2(PublicKey publicKey)
    {
        if (publicKey == null || publicKey.getEncoded() == null)
        {
            throw new IllegalArgumentException("PKOC Credential V2 requires a public key with a DER encoding.");
        }
        return sha256(publicKey.getEncoded());
    }

    // ---------------------------------------------------------------------
    // Derived Identifier truncation (Core §4.5 / §4.6)
    // ---------------------------------------------------------------------

    /**
     * PKOC Derived Identifier (Core §4.5): the rightmost {@code lengthOctets} bytes of the
     * credential, order preserved. Enforces the Standard-mode bounds (8–31 octets).
     */
    public static byte[] deriveIdentifier(byte[] pkocCredential, int lengthOctets)
    {
        return deriveIdentifier(pkocCredential, lengthOctets, false);
    }

    /**
     * Derived Identifier truncation with an explicit trust model.
     *
     * @param pkocCredential the 32-octet PKOC Credential
     * @param lengthOctets   the desired identifier length in octets
     * @param validated      {@code true} to permit the 4–7 octet Validated range (Core §4.6);
     *                       {@code false} enforces the 8–31 Standard range (Core §4.1/§4.5)
     */
    public static byte[] deriveIdentifier(byte[] pkocCredential, int lengthOctets, boolean validated)
    {
        if (pkocCredential == null || pkocCredential.length != PKOC_CREDENTIAL_LENGTH)
        {
            throw new IllegalArgumentException("A PKOC Credential must be exactly 32 octets.");
        }
        int min = validated ? VALIDATED_DERIVED_ID_MIN_OCTETS : DERIVED_ID_MIN_OCTETS;
        if (lengthOctets < min || lengthOctets > DERIVED_ID_MAX_OCTETS)
        {
            throw new IllegalArgumentException("Derived Identifier length " + lengthOctets
                    + " octets is outside the permitted range " + min + "–" + DERIVED_ID_MAX_OCTETS + ".");
        }
        byte[] id = new byte[lengthOctets];
        System.arraycopy(pkocCredential, PKOC_CREDENTIAL_LENGTH - lengthOctets, id, 0, lengthOctets);
        return id;
    }

    // ---------------------------------------------------------------------
    // Representations (Core §4.2)
    // ---------------------------------------------------------------------

    /** Base16 (hex), no {@code 0x} prefix, upper-case (Core §4.2.1). */
    public static String toBase16(byte[] value)
    {
        return bytesToHex(value);
    }

    /** Base64url, padding omitted (Core §4.2.2). */
    public static String toBase64Url(byte[] value)
    {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    /** Decimal, unsigned big-endian (OS2IP), no leading zeros; zero is "0" (Core §4.2.3). */
    public static String toDecimal(byte[] value)
    {
        return new BigInteger(1, value).toString(10);
    }

    /** BER-TLV object: tag {@code 04} (OCTET STRING) over the raw value (Core §4.2.4). */
    public static byte[] toBerTlv(byte[] value)
    {
        return tlv(0x04, value);
    }

    /**
     * OID/Value Discretionary Data Template (Core §4.2.5): {@code 7F4E { 06 <oid> 53 <value> }}.
     *
     * @param oid   one of {@link #OID_PKOC_CREDENTIAL} or {@link #OID_PKOC_DERIVED_IDENTIFIER}
     * @param value the credential or derived-identifier octets (never a Base16 text encoding)
     */
    public static byte[] toDiscretionaryDataTemplate(byte[] oid, byte[] value)
    {
        byte[] oidObj = tlv(0x06, oid);
        byte[] valObj = tlv(0x53, value);
        byte[] inner = concat(oidObj, valObj);
        return tlv(0x7F4E, inner);
    }

    // ---------------------------------------------------------------------
    // Small internal helpers (kept local to avoid new cross-class coupling)
    // ---------------------------------------------------------------------

    private static byte[] sha256(byte[] input)
    {
        try
        {
            return MessageDigest.getInstance("SHA-256").digest(input);
        }
        catch (Exception e)
        {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Minimal DER TLV with a 1- or 2-byte tag and definite short/long length (Core §5.2 length rules). */
    private static byte[] tlv(int tag, byte[] value)
    {
        byte[] tagBytes = (tag > 0xFF)
                ? new byte[] { (byte) (tag >> 8), (byte) tag }
                : new byte[] { (byte) tag };
        byte[] lenBytes = encodeLength(value.length);
        byte[] out = new byte[tagBytes.length + lenBytes.length + value.length];
        int p = 0;
        System.arraycopy(tagBytes, 0, out, p, tagBytes.length); p += tagBytes.length;
        System.arraycopy(lenBytes, 0, out, p, lenBytes.length); p += lenBytes.length;
        System.arraycopy(value, 0, out, p, value.length);
        return out;
    }

    private static byte[] encodeLength(int len)
    {
        if (len < 0x80)                 return new byte[] { (byte) len };
        if (len < 0x100)                return new byte[] { (byte) 0x81, (byte) len };
        return new byte[] { (byte) 0x82, (byte) (len >> 8), (byte) len };
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private static String bytesToHex(byte[] bytes)
    {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++)
        {
            int v = bytes[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    private static byte[] hexToBytes(String hex)
    {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
        {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }
}
