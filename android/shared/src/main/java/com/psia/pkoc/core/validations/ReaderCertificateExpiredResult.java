package com.psia.pkoc.core.validations;

import com.psia.pkoc.core.ValidationResult;

/**
 * Reader Certificate expired or not yet valid — BLE error code 0x09
 * (PKOC BLE Transport Profile 2.0.1, §5.7 / §7.1). The certificate validity
 * window does not include the current time.
 */
public class ReaderCertificateExpiredResult extends ValidationResult
{
    public static final byte BLE_ERROR_CODE = 0x09;

    public ReaderCertificateExpiredResult()
    {
        this("Reader Certificate validity window does not include the current time.");
    }

    public ReaderCertificateExpiredResult(String detail)
    {
        cancelTransaction = true;
        isValid = false;
        message = detail;
    }
}
