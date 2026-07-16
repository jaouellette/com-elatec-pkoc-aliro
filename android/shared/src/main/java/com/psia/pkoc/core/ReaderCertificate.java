package com.psia.pkoc.core;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.psia.pkoc.core.validations.ReaderCertificateExpiredResult;
import com.psia.pkoc.core.validations.ReaderCertificateInvalidResult;
import com.psia.pkoc.core.validations.SuccessResult;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.PrivateKey;
import java.util.Arrays;

/**
 * Reader Certificate — PKOC BLE Transport Profile 2.0.1, §7.1.
 *
 * <p>A fixed-offset, fixed-length 138-byte structure signed by the Site Issuer
 * private key, presented by the reader as TLV {@code 0x10} during the ECDHE
 * handshake. It binds a per-reader signing public key to a Reader Location
 * Identifier and is the BLE realization of the Core's Validated trust model.</p>
 *
 * <pre>
 *  Offset  Len  Field
 *  ------  ---  ---------------------------------------------------------------
 *    0      1   Version (0x01)
 *    1     16   Subject Reader Location Identifier   (MUST match TLV 0x0D)
 *   17     16   Issuer Site Issuer Identifier        (MUST match TLV 0x0E)
 *   33      4   Not-Before (Unix epoch seconds, BE; 0 = no lower bound)
 *   37      4   Not-After  (Unix epoch seconds, BE; 0xFFFFFFFF = no upper bound)
 *   41     33   Reader Public Key (compressed P-256)
 *   74     64   Signature (raw R||S, ECDSA-SHA256 by Site Issuer over bytes 0..73)
 *  ------  ---
 *   138  total
 * </pre>
 *
 * On the wire the TLV header is {@code 0x10 0x81 0x8A} (138-byte value), 141 bytes total.
 */
public final class ReaderCertificate
{
    public static final int VERSION_1            = 0x01;
    public static final int LENGTH               = 138;

    public static final int OFF_VERSION          = 0;
    public static final int OFF_SUBJECT          = 1;   // 16
    public static final int OFF_ISSUER           = 17;  // 16
    public static final int OFF_NOT_BEFORE       = 33;  // 4
    public static final int OFF_NOT_AFTER        = 37;  // 4
    public static final int OFF_READER_PUBKEY    = 41;  // 33 (compressed)
    public static final int OFF_SIGNATURE        = 74;  // 64
    public static final int SIGNED_LENGTH        = 74;  // bytes 0..73 are signed

    public static final long NOT_AFTER_FOREVER   = 0xFFFFFFFFL;

    private final int    version;
    private final byte[] subjectLocationId;   // 16
    private final byte[] issuerId;            // 16
    private final long   notBefore;           // unsigned 32-bit
    private final long   notAfter;            // unsigned 32-bit
    private final byte[] readerPublicKey33;   // compressed P-256
    private final byte[] signature64;         // raw R||S
    private final byte[] raw;                 // full 138-byte encoding

    private ReaderCertificate(byte[] raw138)
    {
        this.raw = raw138;
        this.version           = raw138[OFF_VERSION] & 0xFF;
        this.subjectLocationId = Arrays.copyOfRange(raw138, OFF_SUBJECT, OFF_SUBJECT + 16);
        this.issuerId          = Arrays.copyOfRange(raw138, OFF_ISSUER, OFF_ISSUER + 16);
        this.notBefore         = readU32(raw138, OFF_NOT_BEFORE);
        this.notAfter          = readU32(raw138, OFF_NOT_AFTER);
        this.readerPublicKey33 = Arrays.copyOfRange(raw138, OFF_READER_PUBKEY, OFF_READER_PUBKEY + 33);
        this.signature64       = Arrays.copyOfRange(raw138, OFF_SIGNATURE, OFF_SIGNATURE + 64);
    }

    // ---------------------------------------------------------------------
    // Parsing / construction
    // ---------------------------------------------------------------------

    /**
     * Parse a 138-byte Reader Certificate.
     *
     * @param raw138 the certificate value (the TLV value of tag 0x10, without TLV header)
     * @return a {@code ReaderCertificate}, or {@code null} if the length is wrong
     */
    @Nullable
    public static ReaderCertificate parse(byte[] raw138)
    {
        if (raw138 == null || raw138.length != LENGTH)
        {
            return null;
        }
        return new ReaderCertificate(raw138.clone());
    }

    /**
     * Build and sign a Reader Certificate. Intended for the reader/simulator and
     * for self-tests to mint a Site Issuer-signed certificate; in a real
     * deployment the Site Issuer HSM performs the signature (BLE Appendix A).
     *
     * @param subjectLocationId16   16-byte Reader Location Identifier (TLV 0x0D subject)
     * @param issuerId16            16-byte Site Issuer Identifier (TLV 0x0E)
     * @param notBeforeEpochSeconds lower validity bound (0 = none)
     * @param notAfterEpochSeconds  upper validity bound (0xFFFFFFFF = none)
     * @param readerPublicKey       reader signing public key (33 compressed or 65 uncompressed)
     * @param siteIssuerPrivateKey  Site Issuer private key used to sign bytes 0..73
     * @return a signed {@code ReaderCertificate}, or {@code null} on failure
     */
    @Nullable
    public static ReaderCertificate buildAndSign(
            @NonNull byte[] subjectLocationId16,
            @NonNull byte[] issuerId16,
            long notBeforeEpochSeconds,
            long notAfterEpochSeconds,
            @NonNull byte[] readerPublicKey,
            @NonNull PrivateKey siteIssuerPrivateKey)
    {
        if (subjectLocationId16.length != 16 || issuerId16.length != 16)
        {
            return null;
        }
        byte[] compressed = EcKeyUtil.toCompressed(readerPublicKey);
        if (compressed == null)
        {
            return null;
        }

        byte[] cert = new byte[LENGTH];
        cert[OFF_VERSION] = (byte) VERSION_1;
        System.arraycopy(subjectLocationId16, 0, cert, OFF_SUBJECT, 16);
        System.arraycopy(issuerId16, 0, cert, OFF_ISSUER, 16);
        writeU32(cert, OFF_NOT_BEFORE, notBeforeEpochSeconds);
        writeU32(cert, OFF_NOT_AFTER, notAfterEpochSeconds);
        System.arraycopy(compressed, 0, cert, OFF_READER_PUBKEY, 33);

        byte[] toSign = Arrays.copyOfRange(cert, 0, SIGNED_LENGTH);
        byte[] sig = EcKeyUtil.signRaw(siteIssuerPrivateKey, toSign);
        if (sig == null || sig.length != 64)
        {
            return null;
        }
        System.arraycopy(sig, 0, cert, OFF_SIGNATURE, 64);
        return new ReaderCertificate(cert);
    }

    // ---------------------------------------------------------------------
    // Verification (§7.1). Revocation (error 0x08) is checked separately by the
    // caller against a ReaderRevocationList, since it requires the cached list.
    // ---------------------------------------------------------------------

    /**
     * Verify the certificate's version, subject/issuer binding, validity window,
     * and Site Issuer signature (§7.1).
     *
     * @param expectedLocationId   Reader Location Identifier from TLV 0x0D
     * @param expectedIssuerId     Site Issuer Identifier from TLV 0x0E
     * @param siteIssuerPublicKey  the per-site trust anchor (33 or 65 byte SEC1 key)
     * @param nowEpochSeconds      current time, Unix epoch seconds
     * @return {@link SuccessResult}; otherwise a {@link ReaderCertificateInvalidResult}
     *         (error 0x07) or {@link ReaderCertificateExpiredResult} (error 0x09)
     */
    public ValidationResult verify(
            byte[] expectedLocationId,
            byte[] expectedIssuerId,
            byte[] siteIssuerPublicKey,
            long nowEpochSeconds)
    {
        if (version != VERSION_1)
        {
            return new ReaderCertificateInvalidResult("Unsupported Reader Certificate version: " + version);
        }
        if (expectedLocationId == null || !Arrays.equals(subjectLocationId, expectedLocationId))
        {
            return new ReaderCertificateInvalidResult("Certificate subject does not match Reader Location Identifier (TLV 0x0D)");
        }
        if (expectedIssuerId == null || !Arrays.equals(issuerId, expectedIssuerId))
        {
            return new ReaderCertificateInvalidResult("Certificate issuer does not match Site Issuer Identifier (TLV 0x0E)");
        }
        if (notBefore != 0 && nowEpochSeconds < notBefore)
        {
            return new ReaderCertificateExpiredResult("Reader Certificate is not yet valid");
        }
        if (notAfter != NOT_AFTER_FOREVER && nowEpochSeconds > notAfter)
        {
            return new ReaderCertificateExpiredResult("Reader Certificate has expired");
        }
        if (siteIssuerPublicKey == null)
        {
            return new ReaderCertificateInvalidResult("No Site Issuer public key (trust anchor) provisioned");
        }

        boolean sigOk = EcKeyUtil.verifyRaw(siteIssuerPublicKey, signedPortion(), signature64);
        if (!sigOk)
        {
            return new ReaderCertificateInvalidResult("Reader Certificate signature did not verify against the Site Issuer key");
        }
        return new SuccessResult();
    }

    // ---------------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------------

    public int getVersion()                    { return version; }
    public byte[] getSubjectLocationId()       { return subjectLocationId.clone(); }
    public byte[] getIssuerId()                { return issuerId.clone(); }
    public long getNotBefore()                 { return notBefore; }
    public long getNotAfter()                  { return notAfter; }
    public byte[] getReaderPublicKeyCompressed() { return readerPublicKey33.clone(); }
    public byte[] getReaderPublicKeyUncompressed() { return EcKeyUtil.toUncompressed(readerPublicKey33); }
    public byte[] getSignature()               { return signature64.clone(); }

    /** The full 138-byte certificate encoding (TLV value of tag 0x10). */
    public byte[] encode()                     { return raw.clone(); }

    /** The signed portion (bytes 0..73). */
    public byte[] signedPortion()              { return Arrays.copyOfRange(raw, 0, SIGNED_LENGTH); }

    /** SHA-256 over the 138-byte certificate, used as the discovery-and-pin fingerprint (§7.2). */
    public byte[] fingerprint()                { return CryptoProvider.getSHA256(raw); }

    // ---------------------------------------------------------------------
    // Unsigned 32-bit big-endian helpers
    // ---------------------------------------------------------------------

    private static long readU32(byte[] b, int off)
    {
        return ByteBuffer.wrap(b, off, 4).order(ByteOrder.BIG_ENDIAN).getInt() & 0xFFFFFFFFL;
    }

    private static void writeU32(byte[] b, int off, long value)
    {
        b[off]     = (byte) ((value >>> 24) & 0xFF);
        b[off + 1] = (byte) ((value >>> 16) & 0xFF);
        b[off + 2] = (byte) ((value >>> 8) & 0xFF);
        b[off + 3] = (byte) (value & 0xFF);
    }
}
