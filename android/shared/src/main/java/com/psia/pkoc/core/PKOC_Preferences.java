package com.psia.pkoc.core;

public class PKOC_Preferences
{
    public static final String PKOC_TransmissionType = "PKOC_TransmissionType";
    public static final String PKOC_TransmissionFlow = "PKOC_TransmissionFlow";
    public static final String PKOC_CredentialSet = "PKOC_CredentialSet";
    public static final String PKOC_CreationTime = "PKOC_CreationTime";
    public static final String AutoDiscoverDevices = "AutoDiscoverDevices";
    public static final String EnableRanging = "EnableRanging";
    public static final String RangeValue = "RangeValue";
    public static final String DisplayMAC = "DisplayMAC";
    public static final String ReaderUUID = "ReaderUUID";
    public static final String SiteUUID = "SiteUUID";

    // ECDHE BLE settings keys (SharedPreferences)
    public static final String ECDHE_SitePublicKey = "PKOC_SiteEphemeralKey";
    public static final String ECDHE_SiteId        = "PKOC_Site_ID";
    public static final String ECDHE_ReaderId      = "PKOC_Reader_ID";

    // =========================================================================
    // Built-in defaults for ECDHE Perfect Forward Secrecy (PKOC v3.1.1)
    //
    // These defaults let the app work out of the box for demo/testing.
    // Users can override them in Settings -> ECDHE Perfect Secrecy to test
    // with their own reader/site configuration.
    // =========================================================================

    /** Default Reader Location UUID — ELATEC demo reader */
    public static final String DEFAULT_READER_UUID = "e1a7ec00-0001-4000-8000-00805f9b34fb";

    /** Default Site UUID — ELATEC demo site */
    public static final String DEFAULT_SITE_UUID   = "e1a7ec00-0002-4000-8000-00805f9b34fb";

    /**
     * Default Site Public Key — empty string means "use this device's own
     * PKOC public key as the site key" (self-signed demo mode).
     *
     * When a real site public key is entered in Settings, it overrides this
     * and the reader will verify the device's ECDHE signature against the
     * external site key instead.
     */
    public static final String DEFAULT_SITE_PUBLIC_KEY = "";
}
