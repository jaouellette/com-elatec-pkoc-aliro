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

    // -------------------------------------------------------------------------
    // Mailbox configuration (reader side — sent in EXCHANGE command)
    // -------------------------------------------------------------------------

    /** Boolean: enable mailbox operations in EXCHANGE */
    public static final String MAILBOX_ENABLED = "aliro_mailbox_enabled";

    /** String: operation type — "read", "write", or "set" */
    public static final String MAILBOX_OPERATION = "aliro_mailbox_operation";

    /** Int stored as String: offset into mailbox (0-based decimal) */
    public static final String MAILBOX_OFFSET = "aliro_mailbox_offset";

    /** Int stored as String: length for read/set operations (decimal) */
    public static final String MAILBOX_LENGTH = "aliro_mailbox_length";

    /** Hex string: data bytes for write operation */
    public static final String MAILBOX_DATA = "aliro_mailbox_data";

    /** 2-char hex string: single byte value for set (fill) operation */
    public static final String MAILBOX_SET_VALUE = "aliro_mailbox_set_value";

    /** Boolean: wrap operations in atomic session (0x8C start/stop) */
    public static final String MAILBOX_ATOMIC = "aliro_mailbox_atomic";

    private AliroPreferences() {}
}
