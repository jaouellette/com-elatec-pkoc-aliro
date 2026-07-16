package com.psia.pkoc.core;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;

/**
 * A PKOC-CVC Issuer Key — the Validated-Mode trust anchor (NFC Transport Profile
 * 2.0.1 §5.3, Core §5.8). Each key is identified by the 16-character IIR carried
 * in the certificate's tag {@code 42}, and verifies the certificate signature
 * using the algorithm implied by the key itself (the CVC carries no algorithm id).
 *
 * <p>Supported issuer algorithms in this build: EC P-256 (ES256, mandatory) and
 * RSA (RSASSA-PKCS1-v1_5 with SHA-256). Other curves and ML-DSA parse but are not
 * verified here — configure a P-256 or RSA issuer key, or add a PQC provider.</p>
 */
public final class IssuerKey
{
    public enum Algorithm { EC_P256, RSA, UNSUPPORTED }

    private final String iir;                  // 16-char identifier (matches CVC tag 42)
    private final Algorithm algorithm;
    private final byte[] ecPublicKey65;        // EC_P256: uncompressed 04||X||Y
    private final byte[] rsaModulus;           // RSA
    private final byte[] rsaExponent;          // RSA

    private IssuerKey(String iir, Algorithm alg, byte[] ec65, byte[] mod, byte[] exp)
    {
        this.iir = iir;
        this.algorithm = alg;
        this.ecPublicKey65 = ec65;
        this.rsaModulus = mod;
        this.rsaExponent = exp;
    }

    public static IssuerKey ecP256(@NonNull String iir16, @NonNull byte[] publicKey)
    {
        byte[] u = EcKeyUtil.toUncompressed(publicKey);
        return new IssuerKey(iir16, u != null ? Algorithm.EC_P256 : Algorithm.UNSUPPORTED, u, null, null);
    }

    public static IssuerKey rsa(@NonNull String iir16, @NonNull byte[] modulus, @NonNull byte[] exponent)
    {
        return new IssuerKey(iir16, Algorithm.RSA, null, modulus.clone(), exponent.clone());
    }

    public String getIir()          { return iir; }
    public Algorithm getAlgorithm() { return algorithm; }

    /**
     * Verify a raw CVC signature over the certificate body (the complete {@code 7F4E}
     * TLV) using this issuer key.
     *
     * @param certificateBody the DER-encoded {@code 7F4E} body TLV
     * @param signature       the raw signature value from tag {@code 5F37}
     * @return {@code true} iff the signature verifies
     */
    public boolean verify(byte[] certificateBody, byte[] signature)
    {
        if (certificateBody == null || signature == null)
        {
            return false;
        }
        switch (algorithm)
        {
            case EC_P256:
                // ES256: SHA-256 + P-256 ECDSA over the body, raw r||s.
                return EcKeyUtil.verifyRaw(ecPublicKey65, certificateBody, signature);

            case RSA:
                return verifyRsaPkcs1Sha256(certificateBody, signature);

            default:
                return false;
        }
    }

    private boolean verifyRsaPkcs1Sha256(byte[] body, byte[] signature)
    {
        try
        {
            RSAPublicKeySpec spec = new RSAPublicKeySpec(
                    new BigInteger(1, rsaModulus), new BigInteger(1, rsaExponent));
            PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(spec);
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(pub);
            s.update(body);
            return s.verify(signature);
        }
        catch (Exception e)
        {
            return false;
        }
    }

    // --- Simple hex serialization for persistence (see IssuerKeyStore) ---

    /** {@code IIR|ALG|hex...} — EC: {@code iir|EC_P256|<65-byte pub>}; RSA: {@code iir|RSA|<mod>|<exp>}. */
    public String toStorage()
    {
        StringBuilder sb = new StringBuilder(iir).append('|').append(algorithm.name()).append('|');
        if (algorithm == Algorithm.EC_P256) sb.append(hex(ecPublicKey65));
        else if (algorithm == Algorithm.RSA) sb.append(hex(rsaModulus)).append('|').append(hex(rsaExponent));
        return sb.toString();
    }

    @Nullable
    public static IssuerKey fromStorage(String s)
    {
        try
        {
            String[] parts = s.split("\\|");
            String iir = parts[0];
            Algorithm alg = Algorithm.valueOf(parts[1]);
            if (alg == Algorithm.EC_P256) return ecP256(iir, unhex(parts[2]));
            if (alg == Algorithm.RSA)     return rsa(iir, unhex(parts[2]), unhex(parts[3]));
            return null;
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private static String hex(byte[] b)
    {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        return sb.toString();
    }

    private static byte[] unhex(String s)
    {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
}
