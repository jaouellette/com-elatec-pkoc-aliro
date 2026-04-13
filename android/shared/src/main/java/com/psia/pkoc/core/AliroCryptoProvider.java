package com.psia.pkoc.core;

import static java.lang.System.arraycopy;

import android.util.Log;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

/**
 * Cryptographic helpers for the Aliro Expedited Standard NFC/BLE flow.
 *
 * All operations use NIST P-256 (secp256r1) and are a direct Java port of
 * the ELATEC aliro_flow.h C implementation.
 *
 * Public key convention throughout this class:
 *   - 65 bytes: 0x04 || X (32) || Y (32)  — uncompressed point
 *   - 32 bytes: X component only
 *   - 32 bytes: private scalar
 *
 * Signature convention:
 *   - 64 bytes: R (32) || S (32)  — raw, not DER-encoded
 */
public class AliroCryptoProvider
{
    private static final String TAG = "AliroCryptoProvider";

    // Aliro AID for SELECT command
    public static final byte[] ALIRO_AID = {
        (byte)0xA0, 0x00, 0x00, 0x09, 0x09,
        (byte)0xAC, (byte)0xCE, 0x55, 0x01
    };

    // Fixed footer bytes used in the reader signature hash (from aliro_flow.h)
    private static final byte[] READER_SIG_FOOTER = {
        (byte)0x93, 0x04, 0x41, 0x5D, (byte)0x95, 0x69
    };

    // Fixed footer bytes used in the credential signature hash (from aliro_flow.h)
    private static final byte[] CREDENTIAL_SIG_FOOTER = {
        (byte)0x93, 0x04, 0x4E, (byte)0x88, 0x7B, 0x4C
    };

    /** interface_byte for NFC transport (section 8.3.1.13) */
    public static final byte INTERFACE_BYTE_NFC = 0x5E;

    /** interface_byte for BLE transport (section 8.3.1.13) */
    public static final byte INTERFACE_BYTE_BLE = (byte)0xC3;

    // HKDF salt string "Volatile****" (hex: 566F6C6174696C652A2A2A2A)
    private static final byte[] HKDF_VOLATILE = {
        0x56, 0x6F, 0x6C, 0x61, 0x74, 0x69, 0x6C, 0x65,
        0x2A, 0x2A, 0x2A, 0x2A
    };

    private static final int READER_ID_SIZE  = 32;
    private static final int TRANSACTION_ID_SIZE = 16;
    private static final int GCM_TAG_LENGTH  = 16; // bytes (128 bits)

    // -------------------------------------------------------------------------
    // Random number generation
    // -------------------------------------------------------------------------

    /**
     * Generate cryptographically secure random bytes.
     */
    // Single shared SecureRandom instance — thread-safe after initialization.
    // Avoids entropy pool exhaustion from repeated new SecureRandom() calls
    // during rapid test loops on Android.
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static byte[] generateRandom(int size)
    {
        byte[] out = new byte[size];
        SECURE_RANDOM.nextBytes(out);
        return out;
    }

    // -------------------------------------------------------------------------
    // Ephemeral key pair
    // -------------------------------------------------------------------------

    /**
     * Generate an ephemeral P-256 key pair.
     * @return KeyPair, or null on failure
     */
    public static KeyPair generateEphemeralKeypair()
    {
        try
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            return kpg.generateKeyPair();
        }
        catch (Exception e)
        {
            Log.e(TAG, "generateEphemeralKeypair failed", e);
            return null;
        }
    }

    /**
     * Extract the uncompressed 65-byte public key (0x04 || X || Y) from a KeyPair.
     */
    public static byte[] getUncompressedPublicKey(KeyPair kp)
    {
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        byte[] x = toBytes32(pub.getW().getAffineX());
        byte[] y = toBytes32(pub.getW().getAffineY());
        byte[] out = new byte[65];
        out[0] = 0x04;
        arraycopy(x, 0, out, 1, 32);
        arraycopy(y, 0, out, 33, 32);
        return out;
    }

    // -------------------------------------------------------------------------
    // ECDH shared secret
    // -------------------------------------------------------------------------

    /**
     * Perform ECDH and return only the X coordinate of the shared point (32 bytes).
     *
     * @param ourPrivate  Our ephemeral private key
     * @param theirPublic Their 65-byte uncompressed public key (0x04 || X || Y)
     * @return 32-byte shared secret X coordinate, or null on failure
     */
    public static byte[] ecdhSharedSecretX(PrivateKey ourPrivate, byte[] theirPublic)
    {
        try
        {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH", new BouncyCastleProvider());
            ka.init(ourPrivate);
            ka.doPhase(CryptoProvider.decodePublicKey(theirPublic), true);
            byte[] secret = ka.generateSecret();
            // ECDH output is the X coordinate of the shared point.
            // BouncyCastle returns the raw unsigned big-endian integer which
            // can be 31 bytes (or rarely fewer) when the X coordinate has
            // leading zeros.  Pad to 32 bytes on the left to match the C
            // implementation which always uses a fixed 32-byte buffer.
            // Some providers return the full uncompressed point — take the
            // last 32 bytes in that case.
            if (secret.length > 0 && secret.length <= 32)
            {
                byte[] x = new byte[32];
                arraycopy(secret, 0, x, 32 - secret.length, secret.length);
                return x;
            }
            else if (secret.length > 32)
            {
                byte[] x = new byte[32];
                arraycopy(secret, secret.length - 32, x, 0, 32);
                return x;
            }
            return secret;
        }
        catch (Exception e)
        {
            Log.e(TAG, "ecdhSharedSecretX failed", e);
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Signature: Reader signs for AUTH1
    // -------------------------------------------------------------------------

    /**
     * Compute the Reader's signature for AUTH1.
     *
     * Hash input (in order):
     *   0x4D || 0x20 || readerID (32)
     *   0x86 || 0x20 || udEphPubKeyX (32)
     *   0x87 || 0x20 || readerEphPubKeyX (32)
     *   0x4C || 0x10 || transactionID (16)
     *   READER_SIG_FOOTER (6)
     *
     * @param readerPrivateKey  Reader's static private key (from Android KeyStore or raw bytes)
     * @param readerID          32-byte reader identifier
     * @param udEphPubKeyX      32-byte X of User Device ephemeral public key
     * @param readerEphPubKeyX  32-byte X of Reader ephemeral public key
     * @param transactionID     16-byte transaction ID
     * @return 64-byte raw signature R||S, or null on failure
     */
    public static byte[] computeReaderSignature(
            PrivateKey readerPrivateKey,
            byte[] readerID,
            byte[] udEphPubKeyX,
            byte[] readerEphPubKeyX,
            byte[] transactionID)
    {
        try
        {
            byte[] hash = buildSignatureHash(readerID, udEphPubKeyX, readerEphPubKeyX,
                    transactionID, READER_SIG_FOOTER);
            if (hash == null) return null;

            Signature sig = Signature.getInstance("NONEwithECDSA", new BouncyCastleProvider());
            sig.initSign(readerPrivateKey);
            sig.update(hash);
            byte[] der = sig.sign();
            return derToRawSignature(der);
        }
        catch (Exception e)
        {
            Log.e(TAG, "computeReaderSignature failed", e);
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Signature: Verify credential's AUTH1 response signature
    // -------------------------------------------------------------------------

    /**
     * Verify the User Device's signature from the AUTH1 response.
     *
     * Hash input uses CREDENTIAL_SIG_FOOTER instead of READER_SIG_FOOTER.
     *
     * @param signature         64-byte raw R||S signature from credential
     * @param credentialPubKey  65-byte uncompressed public key of credential
     * @param readerID          32-byte reader identifier
     * @param udEphPubKeyX      32-byte X of User Device ephemeral public key
     * @param readerEphPubKeyX  32-byte X of Reader ephemeral public key
     * @param transactionID     16-byte transaction ID
     * @return true if signature is valid
     */
    public static boolean verifyCredentialSignature(
            byte[] signature,
            byte[] credentialPubKey,
            byte[] readerID,
            byte[] udEphPubKeyX,
            byte[] readerEphPubKeyX,
            byte[] transactionID)
    {
        try
        {
            // Use the pre-hashed value for Bouncy Castle ECDSA verifier
            byte[] hash = buildSignatureHash(readerID, udEphPubKeyX, readerEphPubKeyX,
                    transactionID, CREDENTIAL_SIG_FOOTER);
            if (hash == null) return false;

            byte[] r = new byte[32];
            byte[] s = new byte[32];
            arraycopy(signature, 0, r, 0, 32);
            arraycopy(signature, 32, s, 0, 32);

            org.bouncycastle.crypto.params.ECDomainParameters ecParams =
                    CryptoProvider.getDomainParameters();
            org.bouncycastle.math.ec.ECPoint point =
                    ecParams.getCurve().createPoint(
                            new BigInteger(1, java.util.Arrays.copyOfRange(credentialPubKey, 1, 33)),
                            new BigInteger(1, java.util.Arrays.copyOfRange(credentialPubKey, 33, 65)));
            org.bouncycastle.crypto.params.ECPublicKeyParameters pubParams =
                    new org.bouncycastle.crypto.params.ECPublicKeyParameters(point, ecParams);

            org.bouncycastle.crypto.signers.ECDSASigner signer =
                    new org.bouncycastle.crypto.signers.ECDSASigner();
            signer.init(false, pubParams);
            return signer.verifySignature(hash,
                    new BigInteger(1, r),
                    new BigInteger(1, s));
        }
        catch (Exception e)
        {
            Log.e(TAG, "verifyCredentialSignature failed", e);
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Key derivation: AliroDeriveKeys
    // -------------------------------------------------------------------------

    /**
     * Derive Aliro session keys from the ECDH shared secret.
     *
     * Produces a buffer of the requested size. Key material layout:
     *   offset  0–31 : ExpeditedSKReader
     *   offset 32–63 : ExpeditedSKDevice
     *   offset 64–95 : StepUpSKReader   (request outputSize >= 96)
     *   offset 80–95 : StepUpSKDevice   (request outputSize >= 96)
     *   offset 96–127: BleSK            (request outputSize = 128, BLE only)
     *
     * This is a direct port of AliroDeriveKeys() from aliro_flow.h:
     *   Step 1: ECDH → X coordinate
     *   Step 1.5: X9.63 KDF (SHA-256(secret || counter=1 || transactionID))
     *   Step 2.3: HKDF-Extract with a custom salt
     *   Step 2.6: HKDF-Expand
     *
     * @param ourEphPrivate           Reader's ephemeral private key
     * @param theirEphPublic          65-byte UD ephemeral public key
     * @param outputSize              Bytes of key material to produce (typically 64)
     * @param selectedProtocolVersion 2-byte protocol version chosen in AUTH0
     * @param readerPubKeyX           32-byte X of reader public key
     *                                (issuer public key X if using certificates)
     * @param readerID                32-byte reader identifier
     * @param transactionID           16-byte transaction ID
     * @param readerEphPubKeyX        32-byte X of reader ephemeral public key
     * @param udEphPubKeyX            32-byte X of UD ephemeral public key
     * @param selectProprietaryTLV    Full proprietary TLV from SELECT response
     * @param auth0RspVendorTLV       Vendor extension TLV from AUTH0 response (may be null)
     * @return byte[] of length outputSize, or null on failure
     */
    public static byte[] deriveKeys(
            PrivateKey ourEphPrivate,
            byte[] theirEphPublic,
            int outputSize,
            byte[] selectedProtocolVersion,
            byte[] readerPubKeyX,
            byte[] readerID,
            byte[] transactionID,
            byte[] readerEphPubKeyX,
            byte[] udEphPubKeyX,
            byte[] selectProprietaryTLV,
            byte[] auth0RspVendorTLV,
            byte interfaceByte,
            byte[] flag)
    {
        try
        {
            // Step 1: ECDH shared secret X
            byte[] sharedX = ecdhSharedSecretX(ourEphPrivate, theirEphPublic);
            if (sharedX == null) return null;

            // Step 1.5: X9.63 KDF
            // SHA-256(sharedX || 0x00000001 || transactionID)
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(sharedX);
            sha256.update(new byte[]{0x00, 0x00, 0x00, 0x01}); // counter = 1
            sha256.update(transactionID);
            byte[] z = sha256.digest(); // 32 bytes

            // Step 2.3: HKDF-Extract
            // salt = SHA-256(
            //   readerGroupIdentifierKey.x || "Volatile****" || readerIdentifier ||
            //   interface_byte || 0x5C 0x02 || protocolVersion ||
            //   readerEphPubKey.x || transactionID ||
            //   flag || 0xA5 proprietaryTLV)
            // Per spec section 8.3.1.13:
            //   interface_byte = 0x5E (NFC) or 0xC3 (BLE)
            //   flag = command_parameters || authentication_policy from AUTH0
            sha256.reset();
            sha256.update(readerPubKeyX);           // reader group identifier key X
            sha256.update(HKDF_VOLATILE);            // "Volatile****"
            sha256.update(readerID);                 // reader_identifier
            sha256.update(interfaceByte);            // 0x5E=NFC, 0xC3=BLE
            sha256.update(new byte[]{0x5C, 0x02});  // tag + len for protocol version
            sha256.update(selectedProtocolVersion);  // 2-byte protocol version
            sha256.update(readerEphPubKeyX);         // reader eph pub key X
            sha256.update(transactionID);            // transaction_identifier
            sha256.update(flag);                     // command_parameters || auth_policy
            sha256.update(selectProprietaryTLV);     // 0xA5 proprietary TLV
            byte[] saltHash = sha256.digest(); // 32-byte salt

            // HMAC-SHA256(saltHash, z) → PRK (the HKDF pseudorandom key)
            byte[] prk = hmacSha256(saltHash, z);
            if (prk == null) return null;

            // Step 2.6: HKDF-Expand
            // T(n) = HMAC-SHA256(PRK, T(n-1) || info || n)
            // info = udEphPubKeyX || [auth0CmdVendorTLV] || [auth0RspVendorTLV]
            byte[] output = new byte[outputSize];
            byte[] prev = new byte[0];
            int idx = 0;
            byte n = 1;
            while (idx < outputSize)
            {
                // Build HMAC input: prev || info || n
                int infoLen = 32 // udEphPubKeyX
                        + (auth0RspVendorTLV != null ? auth0RspVendorTLV.length : 0);
                byte[] hmacInput = new byte[prev.length + infoLen + 1];
                int pos = 0;
                arraycopy(prev, 0, hmacInput, pos, prev.length);
                pos += prev.length;
                arraycopy(udEphPubKeyX, 0, hmacInput, pos, 32);
                pos += 32;
                if (auth0RspVendorTLV != null && auth0RspVendorTLV.length > 0)
                {
                    arraycopy(auth0RspVendorTLV, 0, hmacInput, pos, auth0RspVendorTLV.length);
                    pos += auth0RspVendorTLV.length;
                }
                hmacInput[pos] = n;

                prev = hmacSha256(prk, hmacInput);
                if (prev == null) return null;

                int toCopy = Math.min(32, outputSize - idx);
                arraycopy(prev, 0, output, idx, toCopy);
                idx += 32;
                n++;
            }
            return output;
        }
        catch (Exception e)
        {
            Log.e(TAG, "deriveKeys failed", e);
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // AES-GCM encryption / decryption (for EXCHANGE command)
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // GCM for Reader commands (EXCHANGE): uses SKReader, reader_counter IV
    // Section 8.3.1.8: IV = 0x0000000000000000 || reader_counter (starts at 1)
    // -------------------------------------------------------------------------

    /**
     * Build the 12-byte AES-GCM IV for a reader command.
     * Per §8.3.1.8: IV = 0x0000000000000000 || counter (big-endian 4 bytes).
     * Counter SHALL start at 1 and increment by 1 for each subsequent message.
     */
    private static byte[] readerIv(int counter)
    {
        return new byte[]{
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            (byte)(counter >> 24), (byte)(counter >> 16),
            (byte)(counter >> 8),  (byte) counter
        };
    }

    /**
     * Build the 12-byte AES-GCM IV for a device response.
     * Per §8.3.1.6: IV = 0x0000000000000001 || counter (big-endian 4 bytes).
     * Counter SHALL start at 1 and increment by 1 for each subsequent message.
     */
    private static byte[] deviceIv(int counter)
    {
        return new byte[]{
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            (byte)(counter >> 24), (byte)(counter >> 16),
            (byte)(counter >> 8),  (byte) counter
        };
    }

    /**
     * Encrypt a reader command payload (EXCHANGE) with SKReader.
     * Per §8.3.1.8: IV = 0x0000000000000000 || reader_counter.
     *
     * @param skReader  32-byte ExpeditedSKReader
     * @param plaintext payload to encrypt
     * @param counter   reader_counter value for this message (starts at 1)
     * @return ciphertext || 16-byte auth tag, or null on failure
     */
    public static byte[] encryptReaderGcm(byte[] skReader, byte[] plaintext, int counter)
    {
        return gcm(true, skReader, readerIv(counter), plaintext);
    }

    /**
     * Decrypt a reader command payload (EXCHANGE) with SKReader (credential side).
     * Per §8.3.1.9: IV = 0x0000000000000000 || reader_counter.
     *
     * @param skReader         32-byte ExpeditedSKReader
     * @param ciphertextAndTag ciphertext || 16-byte auth tag
     * @param counter          reader_counter value for this message (starts at 1)
     * @return plaintext, or null if authentication tag verification fails
     */
    public static byte[] decryptReaderGcm(byte[] skReader, byte[] ciphertextAndTag, int counter)
    {
        return gcm(false, skReader, readerIv(counter), ciphertextAndTag);
    }

    /**
     * Encrypt a device response payload (AUTH1, EXCHANGE response) with SKDevice.
     * Per §8.3.1.6: IV = 0x0000000000000001 || device_counter.
     *
     * @param skDevice  32-byte ExpeditedSKDevice
     * @param plaintext payload to encrypt
     * @param counter   device_counter value for this message (starts at 1)
     * @return ciphertext || 16-byte auth tag, or null on failure
     */
    public static byte[] encryptDeviceGcm(byte[] skDevice, byte[] plaintext, int counter)
    {
        return gcm(true, skDevice, deviceIv(counter), plaintext);
    }

    /**
     * Decrypt a device response payload (AUTH1, EXCHANGE response) with SKDevice (reader side).
     * Per §8.3.1.7: IV = 0x0000000000000001 || device_counter.
     *
     * @param skDevice         32-byte ExpeditedSKDevice
     * @param ciphertextAndTag ciphertext || 16-byte auth tag
     * @param counter          device_counter value for this message (starts at 1)
     * @return plaintext, or null if authentication tag verification fails
     */
    public static byte[] decryptDeviceGcm(byte[] skDevice, byte[] ciphertextAndTag, int counter)
    {
        return gcm(false, skDevice, deviceIv(counter), ciphertextAndTag);
    }

    // -------------------------------------------------------------------------
    // Convenience overloads: counter=1 (single-EXCHANGE transactions).
    // These remain fully correct for any transaction that sends exactly one
    // EXCHANGE command, which is the common case.
    // -------------------------------------------------------------------------

    /** Encrypt reader command with counter=1. Use the counter overload for multi-EXCHANGE. */
    public static byte[] encryptReaderGcm(byte[] skReader, byte[] plaintext)
    {
        return encryptReaderGcm(skReader, plaintext, 1);
    }

    /** Decrypt reader command with counter=1. Use the counter overload for multi-EXCHANGE. */
    public static byte[] decryptReaderGcm(byte[] skReader, byte[] ciphertextAndTag)
    {
        return decryptReaderGcm(skReader, ciphertextAndTag, 1);
    }

    /** Encrypt device response with counter=1. Use the counter overload for multi-EXCHANGE. */
    public static byte[] encryptDeviceGcm(byte[] skDevice, byte[] plaintext)
    {
        return encryptDeviceGcm(skDevice, plaintext, 1);
    }

    /** Decrypt device response with counter=1. Use the counter overload for multi-EXCHANGE. */
    public static byte[] decryptDeviceGcm(byte[] skDevice, byte[] ciphertextAndTag)
    {
        return decryptDeviceGcm(skDevice, ciphertextAndTag, 1);
    }

    // Keep old names as aliases for backward compatibility with EXCHANGE command
    /** @deprecated use encryptReaderGcm or encryptDeviceGcm */
    public static byte[] encryptGcm(byte[] key, byte[] plaintext)
    {
        return encryptReaderGcm(key, plaintext);
    }

    /** @deprecated use decryptReaderGcm or decryptDeviceGcm */
    public static byte[] decryptGcm(byte[] key, byte[] ciphertextAndTag)
    {
        return decryptDeviceGcm(key, ciphertextAndTag);
    }

    // -------------------------------------------------------------------------
    // Credential-side: sign for AUTH1 response
    // -------------------------------------------------------------------------

    /**
     * Compute the credential's signature for the AUTH1 response.
     * Uses CREDENTIAL_SIG_FOOTER — same hash structure as the reader signature
     * but with the credential footer bytes.
     *
     * @param credentialPrivateKey Credential's static private key
     * @param readerID             32-byte reader identifier
     * @param udEphPubKeyX         32-byte X of UD ephemeral public key
     * @param readerEphPubKeyX     32-byte X of Reader ephemeral public key
     * @param transactionID        16-byte transaction ID
     * @return 64-byte raw R||S signature, or null on failure
     */
    public static byte[] computeCredentialSignature(
            PrivateKey credentialPrivateKey,
            byte[] readerID,
            byte[] udEphPubKeyX,
            byte[] readerEphPubKeyX,
            byte[] transactionID)
    {
        try
        {
            // Build the data to sign — same as the hash input but passed directly
            // to SHA256withECDSA so Android KeyStore can sign it without needing
            // to export the raw private key bytes (which hardware-backed keys forbid).
            byte[] dataToSign = buildSignatureData(readerID, udEphPubKeyX, readerEphPubKeyX,
                    transactionID, CREDENTIAL_SIG_FOOTER);
            if (dataToSign == null) return null;

            // Use SHA256withECDSA — compatible with Android KeyStore hardware-backed keys
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(credentialPrivateKey);
            sig.update(dataToSign);
            byte[] der = sig.sign();
            return derToRawSignature(der);
        }
        catch (Exception e)
        {
            Log.e(TAG, "computeCredentialSignature failed", e);
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Verify the reader's AUTH1 signature (credential side)
    // -------------------------------------------------------------------------

    /**
     * Verify the Reader's signature in AUTH1 (used by the credential app).
     * Uses READER_SIG_FOOTER.
     *
     * @param signature        64-byte raw R||S from AUTH1 command
     * @param readerPubKey     65-byte uncompressed reader public key (or issuer key)
     * @param readerID         32-byte reader identifier
     * @param udEphPubKeyX     32-byte X of UD ephemeral public key
     * @param readerEphPubKeyX 32-byte X of Reader ephemeral public key
     * @param transactionID    16-byte transaction ID
     * @return true if valid
     */
    public static boolean verifyReaderSignature(
            byte[] signature,
            byte[] readerPubKey,
            byte[] readerID,
            byte[] udEphPubKeyX,
            byte[] readerEphPubKeyX,
            byte[] transactionID)
    {
        try
        {
            byte[] hash = buildSignatureHash(readerID, udEphPubKeyX, readerEphPubKeyX,
                    transactionID, READER_SIG_FOOTER);
            if (hash == null) return false;

            byte[] r = new byte[32];
            byte[] s = new byte[32];
            arraycopy(signature, 0, r, 0, 32);
            arraycopy(signature, 32, s, 0, 32);

            org.bouncycastle.crypto.params.ECDomainParameters ecParams =
                    CryptoProvider.getDomainParameters();
            org.bouncycastle.math.ec.ECPoint point =
                    ecParams.getCurve().createPoint(
                            new BigInteger(1, java.util.Arrays.copyOfRange(readerPubKey, 1, 33)),
                            new BigInteger(1, java.util.Arrays.copyOfRange(readerPubKey, 33, 65)));
            org.bouncycastle.crypto.params.ECPublicKeyParameters pubParams =
                    new org.bouncycastle.crypto.params.ECPublicKeyParameters(point, ecParams);

            org.bouncycastle.crypto.signers.ECDSASigner signer =
                    new org.bouncycastle.crypto.signers.ECDSASigner();
            signer.init(false, pubParams);
            return signer.verifySignature(hash,
                    new BigInteger(1, r),
                    new BigInteger(1, s));
        }
        catch (Exception e)
        {
            Log.e(TAG, "verifyReaderSignature failed", e);
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Build the SHA-256 hash used for both reader and credential signatures.
     *
     * Hash = SHA-256(
     *   0x4D || 0x20 || readerID,
     *   0x86 || 0x20 || udEphPubKeyX,
     *   0x87 || 0x20 || readerEphPubKeyX,
     *   0x4C || 0x10 || transactionID,
     *   footer
     * )
     */
    /**
     * Build the raw data buffer that gets fed into the signature.
     * Used with SHA256withECDSA (Android KeyStore) — the Signature engine
     * hashes it internally.
     */
    private static byte[] buildSignatureData(
            byte[] readerID,
            byte[] udEphPubKeyX,
            byte[] readerEphPubKeyX,
            byte[] transactionID,
            byte[] footer)
    {
        try
        {
            int len = 2 + READER_ID_SIZE + 2 + 32 + 2 + 32 + 2 + TRANSACTION_ID_SIZE + footer.length;
            byte[] data = new byte[len];
            int i = 0;
            data[i++] = 0x4D; data[i++] = (byte) READER_ID_SIZE;
            System.arraycopy(readerID, 0, data, i, READER_ID_SIZE); i += READER_ID_SIZE;
            data[i++] = (byte)0x86; data[i++] = 32;
            System.arraycopy(udEphPubKeyX, 0, data, i, 32); i += 32;
            data[i++] = (byte)0x87; data[i++] = 32;
            System.arraycopy(readerEphPubKeyX, 0, data, i, 32); i += 32;
            data[i++] = 0x4C; data[i++] = (byte) TRANSACTION_ID_SIZE;
            System.arraycopy(transactionID, 0, data, i, TRANSACTION_ID_SIZE); i += TRANSACTION_ID_SIZE;
            System.arraycopy(footer, 0, data, i, footer.length);
            return data;
        }
        catch (Exception e)
        {
            Log.e(TAG, "buildSignatureData failed", e);
            return null;
        }
    }

    /**
     * Build the SHA-256 hash of the signature data.
     * Used with NONEwithECDSA (Bouncy Castle, for non-KeyStore keys like the reader).
     */
    private static byte[] buildSignatureHash(
            byte[] readerID,
            byte[] udEphPubKeyX,
            byte[] readerEphPubKeyX,
            byte[] transactionID,
            byte[] footer)
    {
        try
        {
            byte[] data = buildSignatureData(readerID, udEphPubKeyX, readerEphPubKeyX,
                    transactionID, footer);
            if (data == null) return null;
            return MessageDigest.getInstance("SHA-256").digest(data);
        }
        catch (Exception e)
        {
            Log.e(TAG, "buildSignatureHash failed", e);
            return null;
        }
    }

    /**
     * HMAC-SHA-256.
     * Implemented manually using SHA-256 with ipad/opad (matching the C code's
     * inline HKDF implementation exactly).
     *
     * @param key  HMAC key (up to 32 bytes — padded to 64 with zeros if shorter)
     * @param data Data to authenticate
     * @return 32-byte HMAC, or null on failure
     */
    private static byte[] hmacSha256(byte[] key, byte[] data)
    {
        try
        {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            // Pad key to 64 bytes
            byte[] k = new byte[64];
            arraycopy(key, 0, k, 0, Math.min(key.length, 64));

            byte[] ipad = new byte[64];
            byte[] opad = new byte[64];
            for (int i = 0; i < 64; i++)
            {
                ipad[i] = (byte) (k[i] ^ 0x36);
                opad[i] = (byte) (k[i] ^ 0x5C);
            }

            // Inner hash
            sha256.update(ipad);
            sha256.update(data);
            byte[] inner = sha256.digest();

            // Outer hash
            sha256.reset();
            sha256.update(opad);
            sha256.update(inner);
            return sha256.digest();
        }
        catch (Exception e)
        {
            Log.e(TAG, "hmacSha256 failed", e);
            return null;
        }
    }

    /**
     * AES-GCM core (encrypt or decrypt) using Bouncy Castle.
     */
    private static byte[] gcm(boolean encrypt, byte[] key, byte[] iv, byte[] input)
    {
        try
        {
            GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
            AEADParameters params = new AEADParameters(
                    new KeyParameter(key), GCM_TAG_LENGTH * 8, iv);
            gcm.init(encrypt, params);

            byte[] output = new byte[gcm.getOutputSize(input.length)];
            int len = gcm.processBytes(input, 0, input.length, output, 0);
            gcm.doFinal(output, len);
            return output;
        }
        catch (InvalidCipherTextException e)
        {
            Log.e(TAG, "GCM auth tag mismatch", e);
            return null;
        }
        catch (Exception e)
        {
            Log.e(TAG, "gcm operation failed", e);
            return null;
        }
    }

    /**
     * Convert a DER-encoded ECDSA signature to raw 64-byte R||S.
     */
    private static byte[] derToRawSignature(byte[] der)
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(der);
        byte[] r = BigIntegers.asUnsignedByteArray(
                ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue());
        byte[] s = BigIntegers.asUnsignedByteArray(
                ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue());

        byte[] r32 = new byte[32];
        byte[] s32 = new byte[32];
        arraycopy(r, 0, r32, 32 - r.length, r.length);
        arraycopy(s, 0, s32, 32 - s.length, s.length);

        byte[] raw = new byte[64];
        arraycopy(r32, 0, raw, 0, 32);
        arraycopy(s32, 0, raw, 32, 32);
        return raw;
    }

    /**
     * Convert a BigInteger to a fixed 32-byte big-endian array (zero-padded).
     */
    private static byte[] toBytes32(BigInteger n)
    {
        byte[] raw = n.toByteArray();
        byte[] out = new byte[32];
        if (raw.length <= 32)
        {
            arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        }
        else
        {
            // Strip leading zero byte that BigInteger may prepend for sign
            arraycopy(raw, raw.length - 32, out, 0, 32);
        }
        return out;
    }

    // =========================================================================
    // BLE L2CAP: AES-GCM with AAD and per-message counter (§11.8)
    // =========================================================================

    /**
     * AES-128-GCM encrypt with Additional Authenticated Data for BLE notification messages.
     * IV = 0x00000000 00000000 || counter (4 bytes big-endian)
     *
     * @param key       32-byte AES key (BleSKReader or BleSKDevice)
     * @param plaintext Data to encrypt
     * @param aad       Additional authenticated data (Protocol_Header || MsgID || Length_of_plain BE)
     * @param counter   Message counter (starts at 1, increments per message)
     * @return ciphertext || 16-byte GCM tag, or null on failure
     */
    public static byte[] encryptBleGcm(byte[] key, byte[] plaintext, byte[] aad, long counter)
    {
        byte[] iv = new byte[12];
        iv[8]  = (byte) (counter >> 24);
        iv[9]  = (byte) (counter >> 16);
        iv[10] = (byte) (counter >> 8);
        iv[11] = (byte) (counter);
        return gcmWithAad(true, key, iv, plaintext, aad);
    }

    /**
     * AES-128-GCM decrypt with Additional Authenticated Data for BLE notification messages.
     *
     * @param key           32-byte AES key (BleSKReader or BleSKDevice)
     * @param ciphertextTag Ciphertext concatenated with 16-byte GCM tag
     * @param aad           Additional authenticated data
     * @param counter       Message counter used during encryption
     * @return Decrypted plaintext, or null on failure (tag mismatch)
     */
    public static byte[] decryptBleGcm(byte[] key, byte[] ciphertextTag, byte[] aad, long counter)
    {
        byte[] iv = new byte[12];
        iv[8]  = (byte) (counter >> 24);
        iv[9]  = (byte) (counter >> 16);
        iv[10] = (byte) (counter >> 8);
        iv[11] = (byte) (counter);
        return gcmWithAad(false, key, iv, ciphertextTag, aad);
    }

    /**
     * Build the AAD for BLE notification messages per §11.8.
     * AAD = Protocol_Header (1 byte) || Message_ID (1 byte) || plaintext_length (2 bytes BE)
     */
    public static byte[] buildBleAad(int protocolHeader, int messageId, int plaintextLength)
    {
        return new byte[] {
            (byte) protocolHeader,
            (byte) messageId,
            (byte) ((plaintextLength >> 8) & 0xFF),
            (byte) (plaintextLength & 0xFF)
        };
    }

    /**
     * AES-GCM core with AAD support using Bouncy Castle.
     */
    private static byte[] gcmWithAad(boolean encrypt, byte[] key, byte[] iv, byte[] input, byte[] aad)
    {
        try
        {
            GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
            AEADParameters params = new AEADParameters(
                    new KeyParameter(key), GCM_TAG_LENGTH * 8, iv, aad);
            gcm.init(encrypt, params);

            byte[] output = new byte[gcm.getOutputSize(input.length)];
            int len = gcm.processBytes(input, 0, input.length, output, 0);
            gcm.doFinal(output, len);
            return output;
        }
        catch (InvalidCipherTextException e)
        {
            Log.e(TAG, "GCM-AAD auth tag mismatch", e);
            return null;
        }
        catch (Exception e)
        {
            Log.e(TAG, "gcmWithAad operation failed", e);
            return null;
        }
    }

    // =========================================================================
    // HKDF for BleSK derivation (§11.8.1)
    // =========================================================================

    /**
     * HKDF-Extract then Expand to derive BLE session keys from BleSK.
     *
     * BleSKReader = hkdfDeriveKey(bleSK, "BleSKReader", salt)
     * BleSKDevice = hkdfDeriveKey(bleSK, "BleSKDevice", salt)
     * where salt = reader_supported_versions || user_device_selected_version
     *
     * @param ikm   Input keying material (BleSK, 32 bytes)
     * @param info  Info string ("BleSKReader" or "BleSKDevice")
     * @param salt  Salt bytes (versions concatenated)
     * @param length Output key length in bytes (32)
     * @return Derived key, or null on failure
     */
    // -------------------------------------------------------------------------
    // Step-Up session key derivation (ISO 18013-5 §9.1.1.5, as modified by
    // Aliro §8.4.3: IKM = StepUpSK, salt = empty)
    // -------------------------------------------------------------------------

    /**
     * Derives the two session encryption keys used for ENVELOPE/GET RESPONSE
     * messages in the Aliro Step-Up phase.
     *
     * Per Aliro §8.4.3 + ISO 18013-5 §9.1.1.5:
     *   SKDevice = HKDF(IKM=StepUpSK, salt=empty, info="SKDevice", len=32)
     *   SKReader  = HKDF(IKM=StepUpSK, salt=empty, info="SKReader",  len=32)
     *
     * @param stepUpSK  32-byte StepUpSK from deriveKeys() at offset 64
     * @return          byte[64]: SKDevice[0..31] || SKReader[32..63], or null
     */
    public static byte[] deriveStepUpSessionKeys(byte[] stepUpSK)
    {
        if (stepUpSK == null || stepUpSK.length < 32) return null;
        try
        {
            byte[] emptySalt  = new byte[0];
            byte[] skDevice   = hkdfDeriveKey(stepUpSK, "SKDevice", emptySalt, 32);
            byte[] skReader   = hkdfDeriveKey(stepUpSK, "SKReader",  emptySalt, 32);
            if (skDevice == null || skReader == null) return null;
            byte[] result = new byte[64];
            arraycopy(skDevice, 0, result,  0, 32);
            arraycopy(skReader, 0, result, 32, 32);
            return result;
        }
        catch (Exception e)
        {
            Log.e(TAG, "deriveStepUpSessionKeys failed", e);
            return null;
        }
    }

    public static byte[] hkdfDeriveKey(byte[] ikm, String info, byte[] salt, int length)
    {
        try
        {
            // HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)
            byte[] prk = hmacSha256(salt, ikm);
            if (prk == null) return null;

            // HKDF-Expand: T(1) = HMAC-SHA256(PRK, info || 0x01)
            byte[] infoBytes = info.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] output = new byte[length];
            byte[] prev = new byte[0];
            int idx = 0;
            byte n = 1;
            while (idx < length)
            {
                byte[] hmacInput = new byte[prev.length + infoBytes.length + 1];
                int pos = 0;
                arraycopy(prev, 0, hmacInput, pos, prev.length);
                pos += prev.length;
                arraycopy(infoBytes, 0, hmacInput, pos, infoBytes.length);
                pos += infoBytes.length;
                hmacInput[pos] = n;

                prev = hmacSha256(prk, hmacInput);
                if (prev == null) return null;

                int toCopy = Math.min(32, length - idx);
                arraycopy(prev, 0, output, idx, toCopy);
                idx += 32;
                n++;
            }
            return output;
        }
        catch (Exception e)
        {
            Log.e(TAG, "hkdfDeriveKey failed", e);
            return null;
        }
    }
}
