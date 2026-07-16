package com.psia.pkoc.core;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.Nullable;

import org.bouncycastle.util.encoders.Hex;

/**
 * Device-side trust store for PKOC BLE ECDHE per-reader provisioning
 * (PKOC BLE Transport Profile 2.0.1, §7). Maps a Site Identifier to the Site
 * Issuer public key (trust anchor) — and optionally the reader's certificate —
 * imported from a reader's provisioning QR.
 *
 * <p>Kept separate from the Room site/reader tables so no schema migration is
 * needed. The credential app reads {@link #getSiteIssuerKey} when assembling its
 * {@code SiteDto}s so the per-reader path can verify a reader's certificate
 * against the scanned anchor.</p>
 */
public final class PkocBleTrustStore
{
    private PkocBleTrustStore() { }

    private static final String PREFS_NAME = "pkoc_ble_trust";
    private static final String ISSUER_PREFIX = "issuer_"; // + siteId hex
    private static final String CERT_PREFIX   = "cert_";   // + siteId hex

    private static SharedPreferences prefs(Context ctx)
    {
        return ctx.getApplicationContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    private static String key(String prefix, byte[] siteId16)
    {
        return prefix + Hex.toHexString(siteId16);
    }

    /** Store the Site Issuer public key (trust anchor) for a site. */
    public static void putSiteIssuerKey(Context ctx, byte[] siteId16, byte[] issuerPublicKey)
    {
        prefs(ctx).edit().putString(key(ISSUER_PREFIX, siteId16), Hex.toHexString(issuerPublicKey)).apply();
    }

    /** The Site Issuer public key for a site, or {@code null} if none scanned. */
    @Nullable
    public static byte[] getSiteIssuerKey(Context ctx, byte[] siteId16)
    {
        String s = prefs(ctx).getString(key(ISSUER_PREFIX, siteId16), "");
        return s.isEmpty() ? null : Hex.decode(s);
    }

    /** Optionally store the reader's certificate for a site (for pre-pinning). */
    public static void putReaderCertificate(Context ctx, byte[] siteId16, byte[] certificate)
    {
        prefs(ctx).edit().putString(key(CERT_PREFIX, siteId16), Hex.toHexString(certificate)).apply();
    }

    /** The reader certificate stored for a site, or {@code null}. */
    @Nullable
    public static byte[] getReaderCertificate(Context ctx, byte[] siteId16)
    {
        String s = prefs(ctx).getString(key(CERT_PREFIX, siteId16), "");
        return s.isEmpty() ? null : Hex.decode(s);
    }

    /** Whether a Site Issuer anchor has been imported for this site. */
    public static boolean hasSiteIssuerKey(Context ctx, byte[] siteId16)
    {
        return !prefs(ctx).getString(key(ISSUER_PREFIX, siteId16), "").isEmpty();
    }

    public static void clear(Context ctx)
    {
        prefs(ctx).edit().clear().apply();
    }
}
