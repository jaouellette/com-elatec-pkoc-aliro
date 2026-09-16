package com.psia.pkoc.core.validations;

import com.psia.pkoc.core.ValidationResult;

public class UnrecognizedReaderResult extends ValidationResult
{
    public UnrecognizedReaderResult()
    {
        cancelTransaction = true;
        isValid = false;
        errorCode = 0x04; // Unknown Site Issuer (§5.7)
        message = "The reader was not recognized.";
    }
}
