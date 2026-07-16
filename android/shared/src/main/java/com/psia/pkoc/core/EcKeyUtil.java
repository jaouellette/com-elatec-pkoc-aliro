package com.psia.pkoc.core;

import android.util.Log;

import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

/**
 * Small EC key/signature helpers for the BLE per-reader signing-key model
 * (PKOC BLE Transport Profile 2.0.1, §7).
 *
 * <p>This class deliberately builds only on the existing public methods of
 * {@link CryptoProvider} (plus JCA), so it introduces no change to the shared
 * crypto layer and therefore no risk to the PKOC Un-Obfuscated flow or to the
 * Aliro / LEAF Verified code paths. All curve operations are NIST P-256
 * (secp256r1), the PKOC baseline (Core §3.1).</p>
 */
public final class EcKeyUtil
{
    private static final String TAG = "EcKeyUtil";

    private EcKeyUtil() { }

    /**
     * Normalize a SEC1 EC point to the 65-byte uncompressed form
     * ({@code 0x04 || X(32) || Y(32)}). Accepts either a 33-byte compressed
     * point ({@code 0x02/0x03 || X}) or an already-uncompressed 65-byte point.
     *
     * @param keyBytes 33- or 65-byte SEC1 point
     * @return 65-byte uncompressed point, or {@code null} on failure
     */
    public static byte[] toUncompressed(byte[] keyBytes)
    {
        if (keyBytes == null)
        {
            return null;
        }
        if (keyBytes.length == 65 && (keyBytes[0] & 0xFF) == 0x04)
        {
            return keyBytes.clone();
        }
        if (keyBytes.length != 33)
        {
            Log.w(TAG, "toUncompressed: unexpected key length " + keyBytes.length);
            return null;
        }

        // Decompress via the existing CryptoProvider point decoder, then read
        // the affine coordinates back out into a 65-byte uncompressed encoding.
        java.security.Key decoded = CryptoProvider.decodePublicKey(keyBytes);
        if (!(decoded instanceof ECPublicKey))
        {
            Log.w(TAG, "toUncompressed: could not decode compressed point");
            return null;
        }
        ECPublicKey ec = (ECPublicKey) decoded;
        BigInteger x = ec.getW().getAffineX();
        BigInteger y = ec.getW().getAffineY();

        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(BigIntegers.asUnsignedByteArray(32, x), 0, out, 1, 32);
        System.arraycopy(BigIntegers.asUnsignedByteArray(32, y), 0, out, 33, 32);
        return out;
    }

    /**
     * Normalize a SEC1 EC point to the 33-byte compressed form
     * ({@code 0x02/0x03 || X}). Accepts a 33-byte compressed or 65-byte
     * uncompressed point.
     *
     * @param keyBytes 33- or 65-byte SEC1 point
     * @return 33-byte compressed point, or {@code null} on failure
     */
    public static byte[] toCompressed(byte[] keyBytes)
    {
        if (keyBytes == null)
        {
            return null;
        }
        if (keyBytes.length == 33 && ((keyBytes[0] & 0xFF) == 0x02 || (keyBytes[0] & 0xFF) == 0x03))
        {
            return keyBytes.clone();
        }
        if (keyBytes.length != 65 || (keyBytes[0] & 0xFF) != 0x04)
        {
            Log.w(TAG, "toCompressed: unexpected key length " + keyBytes.length);
            return null;
        }

        byte[] out = new byte[33];
        System.arraycopy(keyBytes, 1, out, 1, 32);                 // X
        // Prefix is 0x02 when Y is even, 0x03 when Y is odd.
        byte yLsb = keyBytes[64];
        out[0] = (byte) (((yLsb & 0x01) == 0) ? 0x02 : 0x03);
        return out;
    }

    /**
     * ECDSA-SHA256 signature over {@code data} with the supplied EC private key,
     * returned as raw {@code R || S} (64 bytes) per Core §3.2. The DER output of
     * the JCA signer is converted to raw form using the existing
     * {@link CryptoProvider#RemoveASNHeaderFromSignature(byte[])}.
     *
     * <p>Used by the reader/simulator (and self-tests) to sign a Reader
     * Certificate or revocation list with the Site Issuer private key, and to
     * sign the ECDHE handshake input with the Reader Signing private key.</p>
     *
     * @param privateKey EC private key (P-256)
     * @param data       message to sign (hashed internally with SHA-256)
     * @return 64-byte raw {@code R || S}, or {@code null} on failure
     */
    public static byte[] signRaw(PrivateKey privateKey, byte[] data)
    {
        try
        {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(privateKey);
            s.update(data);
            return CryptoProvider.RemoveASNHeaderFromSignature(s.sign());
        }
        catch (Exception e)
        {
            Log.e(TAG, "signRaw failed", e);
            return null;
        }
    }

    /**
     * Verify a raw {@code R || S} ECDSA-SHA256 signature against a public key in
     * either compressed (33) or uncompressed (65) SEC1 form. Delegates the
     * actual verification to {@link CryptoProvider#validateSignedMessage}.
     *
     * @param publicKey 33- or 65-byte SEC1 public key
     * @param data      original signed message
     * @param rawSig64  64-byte raw {@code R || S} signature
     * @return {@code true} if the signature is valid
     */
    public static boolean verifyRaw(byte[] publicKey, byte[] data, byte[] rawSig64)
    {
        byte[] uncompressed = toUncompressed(publicKey);
        if (uncompressed == null || rawSig64 == null || rawSig64.length != 64)
        {
            return false;
        }
        return CryptoProvider.validateSignedMessage(uncompressed, data, rawSig64);
    }
}
