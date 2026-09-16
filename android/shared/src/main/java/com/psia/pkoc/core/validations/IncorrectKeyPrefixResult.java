package com.psia.pkoc.core.validations;

import com.psia.pkoc.core.ValidationResult;

public class IncorrectKeyPrefixResult extends ValidationResult
{
    public IncorrectKeyPrefixResult()
    {
        cancelTransaction = true;
        isValid = false;
        errorCode = 0x06; // Invalid TLV (§5.7)
        message = "A security key has been received with an invalid prefix.";
    }
}
