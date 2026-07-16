package com.psia.pkoc.core.validations;

import com.psia.pkoc.core.ValidationResult;

/**
 * Reader Certificate revoked — BLE error code 0x08
 * (PKOC BLE Transport Profile 2.0.1, §5.7 / §7.3). The Reader Location
 * Identifier appears in the cached revocation list.
 */
public class ReaderCertificateRevokedResult extends ValidationResult
{
    public static final byte BLE_ERROR_CODE = 0x08;

    public ReaderCertificateRevokedResult()
    {
        this("Reader Certificate has been revoked.");
    }

    public ReaderCertificateRevokedResult(String detail)
    {
        cancelTransaction = true;
        isValid = false;
        message = detail;
    }
}
