package com.psia.pkoc.core;

/**
 * SharedPreferences keys for the PKOC NFC SE V2 card credential
 * (NFC Transport Profile 2.0.1 §5, §8; Core §5). App-wide prefs file so the card
 * (HCE) and reader sides share the same demo Card Issuer trust anchor.
 *
 * <p>Private keys stored as PKCS#8 DER (hex); public keys as 65-byte uncompressed
 * SEC1 points (hex); the PKOC-CVC as its full {@code 7F21} TLV (hex).</p>
 */
public final class PkocNfcPreferences
{
    private PkocNfcPreferences() { }

    public static final String PREFS_NAME = "pkoc_nfc_prefs";

    /** Provisioning mode + enable flag. */
    public static final String MODE        = "pkoc_nfc_mode";
    public static final String MODE_DEMO   = "demo";
    public static final String MODE_IMPORT = "import";
    public static final String ENABLED     = "pkoc_nfc_sev2_enabled"; // default false -> SE V1 only

    /** SE V2 subject signing key pair (public key is the one bound by the CVC). */
    public static final String SEV2_SIGNING_PRIV = "pkoc_nfc_sev2_priv"; // PKCS#8 DER hex
    public static final String SEV2_SIGNING_PUB  = "pkoc_nfc_sev2_pub";  // 65-byte uncompressed hex

    /** Demo Card Issuer key pair (private exists only in MODE_DEMO). */
    public static final String CARD_ISSUER_PRIV = "pkoc_nfc_issuer_priv"; // PKCS#8 DER hex (demo only)
    public static final String CARD_ISSUER_PUB  = "pkoc_nfc_issuer_pub";  // 65-byte uncompressed hex (trust anchor)

    /** The PKOC-CVC (7F21) this card serves, and the IIR that names its Issuer Key. */
    public static final String CVC = "pkoc_nfc_cvc";           // 7F21 hex
    public static final String IIR = "pkoc_nfc_iir";           // 16-char string
}
