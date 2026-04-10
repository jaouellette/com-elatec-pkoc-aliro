package com.pkoc.readersimulator;

/**
 * SharedPreferences keys for Aliro reader configuration.
 * Stored in the simulator's default SharedPreferences.
 */
public class AliroPreferences
{
    /** 32-byte reader private key, stored as lowercase hex string (64 chars) */
    public static final String READER_PRIVATE_KEY = "aliro_reader_private_key";

    /** 32-byte reader identifier, stored as lowercase hex string (64 chars) */
    public static final String READER_ID = "aliro_reader_id";

    /**
     * 65-byte reader issuer public key, stored as lowercase hex string (130 chars).
     * Empty string means no certificate is being used.
     */
    public static final String READER_ISSUER_PUBLIC_KEY = "aliro_reader_issuer_public_key";

    /**
     * Reader certificate bytes, stored as lowercase hex string (variable length).
     * Empty string means no certificate is being used.
     */
    public static final String READER_CERTIFICATE = "aliro_reader_certificate";

    /**
     * DataElementIdentifier to request in the Step-Up phase DeviceRequest.
     * e.g. "access", "administrator", "floor1".
     * Empty string means Step-Up is disabled.
     */
    public static final String STEP_UP_ELEMENT_ID = "aliro_step_up_element_id";

    /**
     * 65-byte issuer public key (130 hex chars) for verifying the credential's
     * Access Document COSE_Sign1 signature. Optional — if blank, signature
     * verification is skipped (document contents still displayed).
     */
    public static final String STEP_UP_ISSUER_PUB_KEY = "aliro_step_up_issuer_pub_key";

    private AliroPreferences() {}
}
