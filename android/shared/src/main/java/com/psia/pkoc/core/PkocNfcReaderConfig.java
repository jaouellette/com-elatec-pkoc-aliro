package com.psia.pkoc.core;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.Nullable;

import org.bouncycastle.util.encoders.Hex;

import java.util.HashSet;
import java.util.Set;

/**
 * Reader-side configuration for the PKOC NFC SE V2 profile (NFC Transport Profile
 * 2.0.1 §4.3, §5.3, §5.5). Stores the operating mode, output selection, and the
 * reader's configured Issuer Keys, and assembles an {@link IssuerKeyStore} for
 * the Validation process.
 *
 * <p>In this simulator a single install acts as both card and reader, so SE V2 is
 * gated by the same enable flag as the card credential, and in demo mode the
 * reader automatically trusts the card's demo Card Issuer key — Validated Mode
 * works out of the box with no manual key entry.</p>
 */
public final class PkocNfcReaderConfig
{
    private PkocNfcReaderConfig() { }

    // Stored in the same app-wide pkoc_nfc_prefs file.
    private static final String READER_VALIDATED        = "pkoc_nfc_reader_validated";
    private static final String READER_REQUIRE_VALIDITY = "pkoc_nfc_reader_require_validity";
    private static final String READER_OUTPUT_TYPE      = "pkoc_nfc_reader_output_type";
    private static final String READER_ID_OCTETS        = "pkoc_nfc_reader_id_octets";
    private static final String READER_EXT_OID          = "pkoc_nfc_reader_ext_oid";       // hex
    private static final String READER_ISSUER_KEYS      = "pkoc_nfc_reader_issuer_keys";   // set of storage strings

    private static SharedPreferences prefs(Context ctx)
    {
        return ctx.getApplicationContext()
                .getSharedPreferences(PkocNfcPreferences.PREFS_NAME, Context.MODE_PRIVATE);
    }

    /** Whether the reader should attempt the SE V2 profile (shared with the card enable). */
    public static boolean isSeV2Enabled(Context ctx)
    {
        return PkocNfcCardCredential.isEnabled(ctx);
    }

    public static boolean isValidatedMode(Context ctx)
    {
        return prefs(ctx).getBoolean(READER_VALIDATED, false);
    }

    public static void setValidatedMode(Context ctx, boolean validated)
    {
        prefs(ctx).edit().putBoolean(READER_VALIDATED, validated).apply();
    }

    public static boolean requireValidity(Context ctx)
    {
        return prefs(ctx).getBoolean(READER_REQUIRE_VALIDITY, false);
    }

    public static void setRequireValidity(Context ctx, boolean require)
    {
        prefs(ctx).edit().putBoolean(READER_REQUIRE_VALIDITY, require).apply();
    }

    public static NfcSeV2ReaderFlow.OutputType outputType(Context ctx)
    {
        String v = prefs(ctx).getString(READER_OUTPUT_TYPE, NfcSeV2ReaderFlow.OutputType.CREDENTIAL.name());
        try { return NfcSeV2ReaderFlow.OutputType.valueOf(v); }
        catch (Exception e) { return NfcSeV2ReaderFlow.OutputType.CREDENTIAL; }
    }

    public static void setOutputType(Context ctx, NfcSeV2ReaderFlow.OutputType type)
    {
        prefs(ctx).edit().putString(READER_OUTPUT_TYPE, type.name()).apply();
    }

    public static int idOctets(Context ctx)
    {
        return prefs(ctx).getInt(READER_ID_OCTETS, 16);
    }

    public static void setIdOctets(Context ctx, int octets)
    {
        prefs(ctx).edit().putInt(READER_ID_OCTETS, octets).apply();
    }

    @Nullable
    public static byte[] extensionOid(Context ctx)
    {
        String hex = prefs(ctx).getString(READER_EXT_OID, "");
        return hex.isEmpty() ? null : Hex.decode(hex);
    }

    public static void setExtensionOid(Context ctx, @Nullable byte[] oid)
    {
        prefs(ctx).edit().putString(READER_EXT_OID, oid == null ? "" : Hex.toHexString(oid)).apply();
    }

    /** Add a configured Issuer Key (IIR + key material) for Validated Mode. */
    public static void addIssuerKey(Context ctx, IssuerKey key)
    {
        SharedPreferences p = prefs(ctx);
        Set<String> set = new HashSet<>(p.getStringSet(READER_ISSUER_KEYS, new HashSet<>()));
        set.add(key.toStorage());
        p.edit().putStringSet(READER_ISSUER_KEYS, set).apply();
    }

    public static void clearIssuerKeys(Context ctx)
    {
        prefs(ctx).edit().remove(READER_ISSUER_KEYS).apply();
    }

    /** Retire a single configured supplier by IIR (leaves all others in place). */
    public static void removeIssuerKey(Context ctx, String iir)
    {
        if (iir == null) return;
        SharedPreferences p = prefs(ctx);
        Set<String> current = p.getStringSet(READER_ISSUER_KEYS, new HashSet<>());
        Set<String> kept = new HashSet<>();
        for (String s : current)
        {
            int bar = s.indexOf('|');
            String entryIir = (bar > 0) ? s.substring(0, bar) : s;
            if (!entryIir.equals(iir)) kept.add(s);
        }
        p.edit().putStringSet(READER_ISSUER_KEYS, kept).apply();
    }

    /** The explicitly configured Issuer Keys (excludes the demo Card Issuer key). */
    public static java.util.List<IssuerKey> listIssuerKeys(Context ctx)
    {
        java.util.List<IssuerKey> out = new java.util.ArrayList<>();
        for (String s : prefs(ctx).getStringSet(READER_ISSUER_KEYS, new HashSet<>()))
        {
            IssuerKey k = IssuerKey.fromStorage(s);
            if (k != null) out.add(k);
        }
        return out;
    }
    /**
     * Build the Issuer Key store for the Validation process: the explicitly
     * configured keys, plus (in demo mode) the card's demo Card Issuer key so a
     * single-install demo validates without manual provisioning.
     */
    public static IssuerKeyStore buildIssuerKeyStore(Context ctx)
    {
        IssuerKeyStore store = new IssuerKeyStore();
        store.loadFromStorage(prefs(ctx).getStringSet(READER_ISSUER_KEYS, new HashSet<>()));

        byte[] demoIssuerPub = PkocNfcCardCredential.getCardIssuerPublicKey(ctx);
        String demoIir = PkocNfcCardCredential.getIir(ctx);
        if (demoIssuerPub != null && demoIir != null && demoIir.length() == 16)
        {
            store.put(IssuerKey.ecP256(demoIir, demoIssuerPub));
        }
        return store;
    }
}
