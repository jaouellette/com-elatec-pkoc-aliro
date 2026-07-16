package com.psia.pkoc.core;

/**
 * SharedPreferences keys for the PKOC BLE per-reader (Validated) credential
 * (PKOC BLE Transport Profile 2.0.1, §7). Kept in a dedicated, app-wide prefs
 * file so the reader (simulator) and device (credential) sides share the same
 * demo trust anchor regardless of which Activity hosts them.
 *
 * <p>Stored formats: private keys as PKCS#8 DER (hex), public keys as 65-byte
 * uncompressed SEC1 points (hex), the Reader Certificate as its 138-byte value (hex).</p>
 */
public final class PkocBlePreferences
{
    private PkocBlePreferences() { }

    /** App-wide (not Activity-scoped) preferences file. */
    public static final String PREFS_NAME = "pkoc_ble_prefs";

    /** Provisioning mode. */
    public static final String MODE = "pkoc_ble_mode";
    public static final String MODE_DEMO = "demo";     // self-signed, zero-config
    public static final String MODE_IMPORT = "import"; // externally provisioned

    /** Whether the per-reader path is enabled at all (falls back to legacy when false). */
    public static final String ENABLED = "pkoc_ble_perreader_enabled";

    /** Reader signing key pair (the key bound by the certificate). */
    public static final String READER_SIGNING_PRIV = "pkoc_ble_reader_signing_priv"; // PKCS#8 DER hex
    public static final String READER_SIGNING_PUB  = "pkoc_ble_reader_signing_pub";  // 65-byte uncompressed hex

    /** Site Issuer key pair. The private key exists only in MODE_DEMO (self-signing). */
    public static final String SITE_ISSUER_PRIV = "pkoc_ble_site_issuer_priv"; // PKCS#8 DER hex (demo only)
    public static final String SITE_ISSUER_PUB  = "pkoc_ble_site_issuer_pub";  // 65-byte uncompressed hex (trust anchor)

    /** The Site Issuer-signed Reader Certificate this reader presents (TLV 0x10). */
    public static final String READER_CERTIFICATE = "pkoc_ble_reader_certificate"; // 138-byte hex

    /** The site / reader-location identifiers the demo certificate is bound to (hex, 16 bytes each). */
    public static final String BOUND_SITE_ID = "pkoc_ble_bound_site_id";
    public static final String BOUND_READER_LOCATION_ID = "pkoc_ble_bound_reader_location_id";
}
