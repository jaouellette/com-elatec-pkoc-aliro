package com.psia.pkoc.core.validations;

import com.psia.pkoc.core.ValidationResult;

/**
 * Reader Certificate verification failed — BLE error code 0x07
 * (PKOC BLE Transport Profile 2.0.1, §5.7). The certificate did not verify
 * against the Site Issuer key, or its subject did not match TLV 0x0D / issuer
 * did not match TLV 0x0E, or its version/structure was invalid.
 */
public class ReaderCertificateInvalidResult extends ValidationResult
{
    /** BLE error code that a reader/device sends in the Error TLV (0x06). */
    public static final byte BLE_ERROR_CODE = 0x07;

    public ReaderCertificateInvalidResult()
    {
        this("Reader Certificate verification failed.");
    }

    public ReaderCertificateInvalidResult(String detail)
    {
        cancelTransaction = true;
        isValid = false;
        message = detail;
    }
}
