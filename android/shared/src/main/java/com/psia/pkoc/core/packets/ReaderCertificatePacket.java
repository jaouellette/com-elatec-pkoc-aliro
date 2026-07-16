package com.psia.pkoc.core.packets;

import com.psia.pkoc.core.ReaderCertificate;
import com.psia.pkoc.core.ValidationResult;
import com.psia.pkoc.core.interfaces.TransactionPacket;
import com.psia.pkoc.core.validations.ReaderCertificateInvalidResult;
import com.psia.pkoc.core.validations.SuccessResult;

import java.util.Arrays;

/**
 * Reader Certificate packet — carries the 138-byte Reader Certificate as
 * TLV {@code 0x10} (PKOC BLE Transport Profile 2.0.1, §5.4 / §7.1).
 *
 * <p>Follows the existing packet convention (constructor takes the TLV value,
 * {@link #encode()} returns it, {@link #validate()} checks structural size).
 * Full cryptographic verification is performed by
 * {@link ReaderCertificate#verify} in the transaction, not here.</p>
 */
public class ReaderCertificatePacket implements TransactionPacket
{
    private final byte[] certificate138;

    public ReaderCertificatePacket(byte[] data)
    {
        certificate138 = Arrays.copyOf(data, data.length);
    }

    @Override
    public byte[] encode()
    {
        return Arrays.copyOf(certificate138, certificate138.length);
    }

    @Override
    public ValidationResult validate()
    {
        if (certificate138.length != ReaderCertificate.LENGTH)
        {
            return new ReaderCertificateInvalidResult(
                "Reader Certificate must be " + ReaderCertificate.LENGTH
                + " bytes, got " + certificate138.length);
        }
        return new SuccessResult();
    }

    /** Parse the packet value into a {@link ReaderCertificate}, or {@code null}. */
    public ReaderCertificate toReaderCertificate()
    {
        return ReaderCertificate.parse(certificate138);
    }
}
