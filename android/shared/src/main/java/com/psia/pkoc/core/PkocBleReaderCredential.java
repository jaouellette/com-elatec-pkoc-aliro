package com.psia.pkoc.core;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import androidx.annotation.Nullable;

import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

/**
 * Manages the reader/simulator's PKOC BLE per-reader (Validated) credential
 * (PKOC BLE Transport Profile 2.0.1, §7): the Reader Signing key pair, the Site
 * Issuer trust anchor, and the Site Issuer-signed Reader Certificate (TLV 0x10).
 *
 * <p>Two provisioning modes, both supported:</p>
 * <ul>
 *   <li><b>Demo (self-signed)</b> — {@link #ensureDemoProvisioned}: generates a
 *       Reader Signing key pair and a demo Site Issuer key pair, self-signs a
 *       Reader Certificate, and persists everything. Zero-config; works out of
 *       the box like the current ECDHE defaults. The device side trusts it by
 *       loading the demo Site Issuer public key as the site's anchor.</li>
 *   <li><b>Import (externally provisioned)</b> — {@link #importProvisioned}:
 *       stores a Reader Certificate, Site Issuer public key, and Reader Signing
 *       private key supplied from a real Appendix A pipeline. No Site Issuer
 *       private key is held.</li>
 * </ul>
 *
 * <p>This class is transport-independent glue over the Stage 1 primitives
 * ({@link ReaderCertificate}, {@link EcKeyUtil}) and does not alter any existing
 * flow; the per-reader path is inert until {@link #isEnabled} is true and a
 * certificate is present.</p>
 */
public final class PkocBleReaderCredential
{
    private static final String TAG = "PkocBleReaderCredential";
    private static final String P256 = "secp256r1";

    private PkocBleReaderCredential() { }

    private static SharedPreferences prefs(Context ctx)
    {
        return ctx.getApplicationContext()
                .getSharedPreferences(PkocBlePreferences.PREFS_NAME, Context.MODE_PRIVATE);
    }

    /** Whether the per-reader (Validated) path is enabled. Default false → legacy behavior. */
    public static boolean isEnabled(Context ctx)
    {
        return prefs(ctx).getBoolean(PkocBlePreferences.ENABLED, false);
    }

    public static void setEnabled(Context ctx, boolean enabled)
    {
        prefs(ctx).edit().putBoolean(PkocBlePreferences.ENABLED, enabled).apply();
    }

    public static boolean isProvisioned(Context ctx)
    {
        SharedPreferences p = prefs(ctx);
        return !p.getString(PkocBlePreferences.READER_CERTIFICATE, "").isEmpty()
                && !p.getString(PkocBlePreferences.READER_SIGNING_PRIV, "").isEmpty()
                && !p.getString(PkocBlePreferences.SITE_ISSUER_PUB, "").isEmpty();
    }

    // ------------------------------------------------------------------
    // Demo (self-signed) provisioning
    // ------------------------------------------------------------------

    /**
     * Ensure a demo credential exists that is bound to the given identifiers.
     * Idempotent: regenerates only if nothing is stored yet or if the stored
     * certificate is bound to different identifiers (e.g. the user changed the
     * site/reader UUID in Settings).
     *
     * @return {@code true} if provisioning succeeded (or was already valid)
     */
    public static boolean ensureDemoProvisioned(Context ctx, byte[] siteId16, byte[] readerLocationId16)
    {
        SharedPreferences p = prefs(ctx);

        boolean boundMatches =
                Arrays.equals(hexOrEmpty(p, PkocBlePreferences.BOUND_SITE_ID), siteId16)
             && Arrays.equals(hexOrEmpty(p, PkocBlePreferences.BOUND_READER_LOCATION_ID), readerLocationId16);

        if (isProvisioned(ctx)
                && PkocBlePreferences.MODE_DEMO.equals(p.getString(PkocBlePreferences.MODE, ""))
                && boundMatches)
        {
            return true; // already good
        }

        try
        {
            // Reader Signing key pair (exportable P-256).
            KeyPair readerKp = CryptoProvider.CreateTransientKeyPair();
            KeyPair issuerKp = CryptoProvider.CreateTransientKeyPair();
            if (readerKp == null || issuerKp == null)
            {
                Log.e(TAG, "Key generation failed");
                return false;
            }

            byte[] readerPubUncompressed = CryptoProvider.getUncompressedPublicKeyBytes(readerKp.getPublic().getEncoded());
            byte[] issuerPubUncompressed = CryptoProvider.getUncompressedPublicKeyBytes(issuerKp.getPublic().getEncoded());

            // Self-sign a Reader Certificate with the demo Site Issuer key.
            ReaderCertificate cert = ReaderCertificate.buildAndSign(
                    siteIdSubjectOrder(readerLocationId16),   // subject = Reader Location Identifier
                    copy16(siteId16),                          // issuer  = Site Issuer Identifier
                    0L,                                        // Not-Before: none
                    ReaderCertificate.NOT_AFTER_FOREVER,       // Not-After: none (demo convenience)
                    readerPubUncompressed,
                    issuerKp.getPrivate());
            if (cert == null)
            {
                Log.e(TAG, "Demo certificate build/sign failed");
                return false;
            }

            p.edit()
                    .putString(PkocBlePreferences.MODE, PkocBlePreferences.MODE_DEMO)
                    .putString(PkocBlePreferences.READER_SIGNING_PRIV, Hex.toHexString(readerKp.getPrivate().getEncoded()))
                    .putString(PkocBlePreferences.READER_SIGNING_PUB, Hex.toHexString(readerPubUncompressed))
                    .putString(PkocBlePreferences.SITE_ISSUER_PRIV, Hex.toHexString(issuerKp.getPrivate().getEncoded()))
                    .putString(PkocBlePreferences.SITE_ISSUER_PUB, Hex.toHexString(issuerPubUncompressed))
                    .putString(PkocBlePreferences.READER_CERTIFICATE, Hex.toHexString(cert.encode()))
                    .putString(PkocBlePreferences.BOUND_SITE_ID, Hex.toHexString(copy16(siteId16)))
                    .putString(PkocBlePreferences.BOUND_READER_LOCATION_ID, Hex.toHexString(copy16(readerLocationId16)))
                    .apply();

            Log.i(TAG, "Demo per-reader credential provisioned (self-signed).");
            return true;
        }
        catch (Exception e)
        {
            Log.e(TAG, "ensureDemoProvisioned failed", e);
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Import (externally provisioned)
    // ------------------------------------------------------------------

    /**
     * Store an externally provisioned credential (real Appendix A pipeline).
     *
     * @param certificate138        the 138-byte Reader Certificate value (TLV 0x10)
     * @param siteIssuerPublicKey   the Site Issuer public key (33 or 65-byte SEC1)
     * @param readerSigningPrivate  the reader signing private key, PKCS#8 DER or raw 32-byte scalar
     * @return {@code true} if stored; {@code false} on parse/validation failure
     */
    public static boolean importProvisioned(
            Context ctx,
            byte[] certificate138,
            byte[] siteIssuerPublicKey,
            byte[] readerSigningPrivate)
    {
        try
        {
            ReaderCertificate cert = ReaderCertificate.parse(certificate138);
            if (cert == null)
            {
                Log.e(TAG, "Imported certificate is not 138 bytes");
                return false;
            }
            byte[] issuerPubUncompressed = EcKeyUtil.toUncompressed(siteIssuerPublicKey);
            if (issuerPubUncompressed == null)
            {
                Log.e(TAG, "Imported Site Issuer public key is invalid");
                return false;
            }

            PrivateKey readerPriv = privateKeyFromBytes(readerSigningPrivate);
            if (readerPriv == null)
            {
                Log.e(TAG, "Imported reader signing private key is invalid");
                return false;
            }

            // Soft sanity check: the certificate should verify against the supplied issuer key.
            long now = System.currentTimeMillis() / 1000L;
            ValidationResult vr = cert.verify(cert.getSubjectLocationId(), cert.getIssuerId(), issuerPubUncompressed, now);
            if (!vr.isValid)
            {
                Log.w(TAG, "Imported certificate did not verify against the supplied Site Issuer key: " + vr.message
                        + " (storing anyway; check your provisioning inputs).");
            }

            prefs(ctx).edit()
                    .putString(PkocBlePreferences.MODE, PkocBlePreferences.MODE_IMPORT)
                    .putString(PkocBlePreferences.READER_SIGNING_PRIV, Hex.toHexString(readerPriv.getEncoded()))
                    .remove(PkocBlePreferences.SITE_ISSUER_PRIV) // no issuer private key in import mode
                    .putString(PkocBlePreferences.SITE_ISSUER_PUB, Hex.toHexString(issuerPubUncompressed))
                    .putString(PkocBlePreferences.READER_CERTIFICATE, Hex.toHexString(cert.encode()))
                    .putString(PkocBlePreferences.BOUND_SITE_ID, Hex.toHexString(cert.getIssuerId()))
                    .putString(PkocBlePreferences.BOUND_READER_LOCATION_ID, Hex.toHexString(cert.getSubjectLocationId()))
                    .apply();

            Log.i(TAG, "Imported per-reader credential stored.");
            return true;
        }
        catch (Exception e)
        {
            Log.e(TAG, "importProvisioned failed", e);
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Accessors used by the reader (simulator) and device (credential) sides
    // ------------------------------------------------------------------

    /** The 138-byte Reader Certificate to present as TLV 0x10, or {@code null}. */
    @Nullable
    public static byte[] getReaderCertificateBytes(Context ctx)
    {
        String hex = prefs(ctx).getString(PkocBlePreferences.READER_CERTIFICATE, "");
        return hex.isEmpty() ? null : Hex.decode(hex);
    }

    /** The Site Issuer public key (trust anchor, 65-byte uncompressed), or {@code null}. */
    @Nullable
    public static byte[] getSiteIssuerPublicKey(Context ctx)
    {
        String hex = prefs(ctx).getString(PkocBlePreferences.SITE_ISSUER_PUB, "");
        return hex.isEmpty() ? null : Hex.decode(hex);
    }

    /** The reader signing private key used to sign the ECDHE handshake, or {@code null}. */
    @Nullable
    public static PrivateKey getReaderSigningPrivateKey(Context ctx)
    {
        String hex = prefs(ctx).getString(PkocBlePreferences.READER_SIGNING_PRIV, "");
        if (hex.isEmpty()) return null;
        return privateKeyFromBytes(Hex.decode(hex));
    }

    /**
     * Sign the ECDHE handshake input with the reader signing private key,
     * returning raw {@code R || S} (64 bytes). Used by the reader in place of the
     * legacy site-key signature when the per-reader path is active.
     *
     * @return 64-byte raw signature, or {@code null} if unavailable
     */
    @Nullable
    public static byte[] signHandshake(Context ctx, byte[] toSign)
    {
        PrivateKey key = getReaderSigningPrivateKey(ctx);
        if (key == null) return null;
        return EcKeyUtil.signRaw(key, toSign);
    }

    // ------------------------------------------------------------------
    // Key (de)serialization helpers
    // ------------------------------------------------------------------

    @Nullable
    private static PrivateKey privateKeyFromBytes(byte[] keyBytes)
    {
        if (keyBytes == null) return null;
        // Try PKCS#8 DER first.
        try
        {
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        }
        catch (Exception ignored) { /* fall through */ }

        // Then try a raw 32-byte P-256 scalar.
        if (keyBytes.length == 32)
        {
            try
            {
                AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
                ap.init(new java.security.spec.ECGenParameterSpec(P256));
                ECParameterSpec p256 = ap.getParameterSpec(ECParameterSpec.class);
                ECPrivateKeySpec spec = new ECPrivateKeySpec(new BigInteger(1, keyBytes), p256);
                return KeyFactory.getInstance("EC").generatePrivate(spec);
            }
            catch (Exception e)
            {
                Log.e(TAG, "raw private-key reconstruction failed", e);
            }
        }
        return null;
    }

    private static byte[] hexOrEmpty(SharedPreferences p, String key)
    {
        String hex = p.getString(key, "");
        return hex.isEmpty() ? new byte[0] : Hex.decode(hex);
    }

    private static byte[] copy16(byte[] in)
    {
        byte[] out = new byte[16];
        System.arraycopy(in, 0, out, 0, Math.min(16, in.length));
        return out;
    }

    // Subject of the certificate is the Reader Location Identifier.
    private static byte[] siteIdSubjectOrder(byte[] readerLocationId16)
    {
        return copy16(readerLocationId16);
    }
}
