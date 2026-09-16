package com.psia.pkoc.core.validations;

import com.psia.pkoc.core.ValidationResult;

public class InvalidSignatureResult extends ValidationResult
{
    public InvalidSignatureResult()
    {
        cancelTransaction = true;
        isValid = false;
        errorCode = 0x02; // Signature Verification Failed (§5.7)
        message = "Failed to validate signature with provided public key";
    }
}
