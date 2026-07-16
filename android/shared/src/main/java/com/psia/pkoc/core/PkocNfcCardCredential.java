package com.psia.pkoc.core;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import androidx.annotation.Nullable;

import org.bouncycastle.util.encoders.Hex;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

/**
 * Manages the card/HCE side PKOC NFC SE V2 credential (NFC Transport Profile
 * 2.0.1 §5, §8; Core §5): the SE V2 subject signing key, the Card Issuer trust
 * anchor, and the Site Issuer-signed PKOC-CVC the card serves on GET DATA (PKOC-CVC).
 *
 * <p>Two provisioning modes, mirroring the BLE per-reader credential:</p>
 * <ul>
 *   <li><b>Demo</b> ({@link #ensureDemoProvisioned}) — generates an SE V2 key pair
 *       and a demo Card Issuer key pair, self-signs a PKOC-CVC (with a demo UUID
 *       extension credential), and persists everything. Zero-config.</li>
 *   <li><b>Import</b> ({@link #importProvisioned}) — stores an externally issued
 *       PKOC-CVC and the matching SE V2 private key.</li>
 * </ul>
 *
 * <p>Inert until {@link #isEnabled} is true; SE V1 (SELECT + AUTHENTICATE) is
 * unaffected.</p>
 */
public final class PkocNfcCardCredential
{
    private static final String TAG = "PkocNfcCardCredential";

    /** Fixed demo IIR (private format, 16 chars, A–Z/0–9). */
    public static final String DEMO_IIR = "01000ELATEC00001";
    private static final String DEMO_SUBJECT_REF = "CARD000000000001";

    private PkocNfcCardCredential() { }

    private static SharedPreferences prefs(Context ctx)
    {
        return ctx.getApplicationContext()
                .getSharedPreferences(PkocNfcPreferences.PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static boolean isEnabled(Context ctx)
    {
        return prefs(ctx).getBoolean(PkocNfcPreferences.ENABLED, false);
    }

    public static void setEnabled(Context ctx, boolean enabled)
    {
        prefs(ctx).edit().putBoolean(PkocNfcPreferences.ENABLED, enabled).apply();
    }

    public static boolean isProvisioned(Context ctx)
    {
        SharedPreferences p = prefs(ctx);
        return !p.getString(PkocNfcPreferences.CVC, "").isEmpty()
                && !p.getString(PkocNfcPreferences.SEV2_SIGNING_PRIV, "").isEmpty();
    }

    // ------------------------------------------------------------------
    // Demo (self-signed) provisioning
    // ------------------------------------------------------------------

    /** Ensure a demo SE V2 credential + self-signed PKOC-CVC exists. Idempotent. */
    public static boolean ensureDemoProvisioned(Context ctx)
    {
        SharedPreferences p = prefs(ctx);
        if (isProvisioned(ctx) && PkocNfcPreferences.MODE_DEMO.equals(p.getString(PkocNfcPreferences.MODE, "")))
        {
            return true;
        }
        try
        {
            KeyPair subjectKp = CryptoProvider.CreateTransientKeyPair();
            KeyPair issuerKp  = CryptoProvider.CreateTransientKeyPair();
            if (subjectKp == null || issuerKp == null) return false;

            byte[] subjectPub = CryptoProvider.getUncompressedPublicKeyBytes(subjectKp.getPublic().getEncoded());
            byte[] issuerPub  = CryptoProvider.getUncompressedPublicKeyBytes(issuerKp.getPublic().getEncoded());

            int validFrom = todayYyyymmdd();
            int validTo   = validFrom + 100000; // +10 years (YYYYMMDD arithmetic on the year field)

            // Demo extension credential: a 16-byte UUID = the 16-octet Derived Identifier.
            List<PkocCvc.Extension> exts = new ArrayList<>();
            byte[] credential = PkocCredentialDerivation.deriveCredentialV1(subjectPub);
            byte[] uuid16 = PkocCredentialDerivation.deriveIdentifier(credential, 16);
            exts.add(new PkocCvc.Extension(PkocCvc.OID_EXT_UUID, uuid16));

            PkocCvc cvc = PkocCvc.buildAndSignEcP256(
                    DEMO_IIR, subjectPub, DEMO_SUBJECT_REF, validFrom, validTo, exts, issuerKp.getPrivate());
            if (cvc == null) return false;

            p.edit()
                    .putString(PkocNfcPreferences.MODE, PkocNfcPreferences.MODE_DEMO)
                    .putString(PkocNfcPreferences.SEV2_SIGNING_PRIV, Hex.toHexString(subjectKp.getPrivate().getEncoded()))
                    .putString(PkocNfcPreferences.SEV2_SIGNING_PUB, Hex.toHexString(subjectPub))
                    .putString(PkocNfcPreferences.CARD_ISSUER_PRIV, Hex.toHexString(issuerKp.getPrivate().getEncoded()))
                    .putString(PkocNfcPreferences.CARD_ISSUER_PUB, Hex.toHexString(issuerPub))
                    .putString(PkocNfcPreferences.CVC, Hex.toHexString(cvc.encode()))
                    .putString(PkocNfcPreferences.IIR, DEMO_IIR)
                    .apply();

            Log.i(TAG, "Demo SE V2 card credential provisioned (self-signed PKOC-CVC).");
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
     * Store an externally issued PKOC-CVC and the matching SE V2 private key.
     *
     * @param cvcBytes          the {@code 7F21} PKOC-CVC value
     * @param seV2PrivatePkcs8  the SE V2 subject private key (PKCS#8 DER)
     */
    public static boolean importProvisioned(Context ctx, byte[] cvcBytes, byte[] seV2PrivatePkcs8)
    {
        try
        {
            PkocCvc cvc = PkocCvc.parse(cvcBytes);
            if (cvc == null)
            {
                Log.e(TAG, "Imported PKOC-CVC could not be parsed");
                return false;
            }
            PrivateKey key = privateKeyFromPkcs8(seV2PrivatePkcs8);
            if (key == null)
            {
                Log.e(TAG, "Imported SE V2 private key invalid");
                return false;
            }

            prefs(ctx).edit()
                    .putString(PkocNfcPreferences.MODE, PkocNfcPreferences.MODE_IMPORT)
                    .putString(PkocNfcPreferences.SEV2_SIGNING_PRIV, Hex.toHexString(key.getEncoded()))
                    .remove(PkocNfcPreferences.CARD_ISSUER_PRIV)
                    .putString(PkocNfcPreferences.CVC, Hex.toHexString(cvc.encode()))
                    .putString(PkocNfcPreferences.IIR, cvc.getIir() == null ? "" : cvc.getIir())
                    .apply();

            Log.i(TAG, "Imported SE V2 card credential stored.");
            return true;
        }
        catch (Exception e)
        {
            Log.e(TAG, "importProvisioned failed", e);
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /** The PKOC-CVC (7F21) served on GET DATA (PKOC-CVC), or {@code null}. */
    @Nullable
    public static byte[] getCvcBytes(Context ctx)
    {
        String hex = prefs(ctx).getString(PkocNfcPreferences.CVC, "");
        return hex.isEmpty() ? null : Hex.decode(hex);
    }

    /** The SE V2 subject signing private key, or {@code null}. */
    @Nullable
    public static PrivateKey getSeV2SigningPrivateKey(Context ctx)
    {
        String hex = prefs(ctx).getString(PkocNfcPreferences.SEV2_SIGNING_PRIV, "");
        return hex.isEmpty() ? null : privateKeyFromPkcs8(Hex.decode(hex));
    }

    /** The demo Card Issuer public key (trust anchor), or {@code null} (import mode). */
    @Nullable
    public static byte[] getCardIssuerPublicKey(Context ctx)
    {
        String hex = prefs(ctx).getString(PkocNfcPreferences.CARD_ISSUER_PUB, "");
        return hex.isEmpty() ? null : Hex.decode(hex);
    }

    /** The IIR that names this card's Issuer Key. */
    public static String getIir(Context ctx)
    {
        return prefs(ctx).getString(PkocNfcPreferences.IIR, "");
    }

    // ------------------------------------------------------------------
    // Key helpers
    // ------------------------------------------------------------------

    @Nullable
    private static PrivateKey privateKeyFromPkcs8(byte[] pkcs8)
    {
        try
        {
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        }
        catch (Exception e)
        {
            Log.e(TAG, "private key parse failed", e);
            return null;
        }
    }

    private static int todayYyyymmdd()
    {
        Calendar c = Calendar.getInstance();
        return c.get(Calendar.YEAR) * 10000 + (c.get(Calendar.MONTH) + 1) * 100 + c.get(Calendar.DAY_OF_MONTH);
    }
}
