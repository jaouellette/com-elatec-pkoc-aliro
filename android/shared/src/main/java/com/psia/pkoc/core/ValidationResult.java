package com.psia.pkoc.core;


public class ValidationResult
{
    public Boolean cancelTransaction = true;
    public Boolean isValid = true;
    public String message = "";
    /** BLE error code to send in the Error TLV (0x06) before disconnecting, per §5.7. */
    public byte errorCode = (byte) 0xFF;

    public ValidationResult()
    {
    }

    public ValidationResult(boolean _cancelTransaction, boolean _isValid, String _message)
    {
        cancelTransaction = _cancelTransaction;
        isValid = _isValid;
        message = _message;
    }
}
