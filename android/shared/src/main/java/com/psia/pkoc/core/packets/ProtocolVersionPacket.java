package com.psia.pkoc.core.packets;

import com.psia.pkoc.core.PKOC_EncryptionType;
import com.psia.pkoc.core.ValidationResult;
import com.psia.pkoc.core.interfaces.TransactionPacket;
import com.psia.pkoc.core.validations.SizeMismatchResult;
import com.psia.pkoc.core.validations.SuccessResult;

public class ProtocolVersionPacket implements TransactionPacket
{
    private byte majorVersion;
    private byte minorVersion;
    private short vendorSubVersion;
    private boolean ccmSupported = true;
    private boolean readerCertificateSupported = false;

    public ProtocolVersionPacket(byte[] data)
    {
        if (data.length == 2)
        {
            vendorSubVersion = (short)(((data[0] & 0xFF) << 8) | (data[1] & 0xFF));
            return;
        }

        if (data.length == 6)
        {
            majorVersion = data[0];
            minorVersion = data[1];
            vendorSubVersion = (short) (((data[2] & 0xFF) << 8) | (data[3] & 0xFF));

            int featureBits = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);

            ccmSupported = (featureBits & 0x0001) != 0;
            readerCertificateSupported = (featureBits & 0x0002) != 0;
        }
    }

    public ProtocolVersionPacket(byte _majorVersion, byte _minorVersion, short _vendorSubVersion, boolean _ccmSupported, boolean _readerCertificateSupported)
    {
        majorVersion = _majorVersion;
        minorVersion = _minorVersion;
        vendorSubVersion = _vendorSubVersion;
        ccmSupported = _ccmSupported;
        readerCertificateSupported = _readerCertificateSupported;
    }

    public byte getMajorVersion()
    {
        return majorVersion;
    }

    public byte getMinorVersion()
    {
        return minorVersion;
    }

    public short getVendorVersion()
    {
        return vendorSubVersion;
    }

    public boolean isReaderCertificateSupported()
    {
        return readerCertificateSupported;
    }

    public PKOC_EncryptionType getEncryptionType()
    {
        if (ccmSupported)
        {
            return PKOC_EncryptionType.CCM;
        }

        return PKOC_EncryptionType.NotSpecified;
    }

    public byte[] encode()
    {
        byte[] data = new byte[6];

        data[0] = majorVersion;
        data[1] = minorVersion;

        data[2] = (byte)((vendorSubVersion >> 8) & 0xFF);
        data[3] = (byte)(vendorSubVersion & 0xFF);

        int featureBits = 0;
        if (ccmSupported)
        {
            featureBits |= 0x0001;
        }
        if (readerCertificateSupported)
        {
            featureBits |= 0x0002;
        }

        data[4] = (byte)((featureBits >> 8) & 0xFF);
        data[5] = (byte)(featureBits & 0xFF);

        return data;
    }

    public ValidationResult validate()
    {
        var sizeMismatch = new SizeMismatchResult(encode().length, 2, 6);
        if (sizeMismatch.isValid == false)
        {
            return sizeMismatch;
        }

        return new SuccessResult();
    }
}
