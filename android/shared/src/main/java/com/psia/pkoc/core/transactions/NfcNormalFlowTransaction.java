package com.psia.pkoc.core.transactions;

import com.psia.pkoc.core.NFC_Packet;
import com.psia.pkoc.core.NFC_PacketType;
import com.psia.pkoc.core.TLVProvider;
import com.psia.pkoc.core.ValidationResult;
import com.psia.pkoc.core.messages.ReaderResponseMessage;
import com.psia.pkoc.core.validations.SuccessResult;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.nio.ByteBuffer;

public class NfcNormalFlowTransaction extends NormalFlowTransaction<NFC_Packet>
{
    public static final String SELECT_COMMAND_STRING = "00a4040008a00000089800000100";
    public static final String AUTHENTICATION_COMMAND_PREFIX_STRING = "80800001";
    public static final byte[] SUCCESS_STATUS = Hex.decode("9000");
    public static final byte[] GENERAL_ERROR_STATUS = Hex.decode("6f00");
    public static final String SUPPORTED_PROTOCOL_VERSION = "0100";

    private enum State
    {
        INITIAL,
        AWAITING_AUTHENTICATION,
        SUCCESS,
        FAILED
    }

    private State readerState = State.INITIAL;
    private final boolean isDevice;
    private boolean transactionSuccessful = false; // Used for device mode

    public NfcNormalFlowTransaction(boolean _isDevice)
    {
        super(_isDevice);
        this.isDevice = _isDevice;
    }

    @Override
    public ValidationResult processNewData(byte[] data)
    {
        var packets = TLVProvider.GetNfcValues(data);
        for (var packet : packets)
        {
            var vr = processNewPacket(packet);
            if (!vr.isValid)
            {
                return vr;
            }
        }

        return new SuccessResult();
    }

    public byte[] processDeviceCommand(byte[] command)
    {
        if (Arrays.areEqual(command, Hex.decode(SELECT_COMMAND_STRING)))
        {
            byte[] protocolVersion = Hex.decode(SUPPORTED_PROTOCOL_VERSION);
            byte[] protocolVersionTlv = TLVProvider.GetNfcTLV(NFC_PacketType.ProtocolVersion, protocolVersion);
            return Arrays.concatenate(protocolVersionTlv, SUCCESS_STATUS);
        }

        var apduHex = Hex.toHexString(command);
        if (Hex.toHexString(command).startsWith(AUTHENTICATION_COMMAND_PREFIX_STRING))
        {
            String authCommandHexData = apduHex.substring(AUTHENTICATION_COMMAND_PREFIX_STRING.length() + 2);
            var vr = processNewData(Hex.decode(authCommandHexData));

            if (vr.isValid)
            {
                transactionSuccessful = true;
                return Arrays.concatenate(toWrite(), SUCCESS_STATUS);
            }
        }
        return GENERAL_ERROR_STATUS;
    }

    public void processReaderResponse(byte[] response)
    {
        if (isDevice)
        {
            return;
        }

        switch (readerState)
        {
            case INITIAL:
                if (isAcceptedSelectResponse(response))
                {
                    readerState = State.AWAITING_AUTHENTICATION;
                }
                else
                {
                    readerState = State.FAILED;
                }
                break;
            case AWAITING_AUTHENTICATION:
                if (response.length > 2 && response[response.length - 2] == SUCCESS_STATUS[0] && response[response.length - 1] == SUCCESS_STATUS[1])
                {
                    byte[] responseData = Arrays.copyOfRange(response, 0, response.length - 2);
                    if (responseData.length > 0)
                    {
                        var vr = processNewData(responseData);
                        if (!vr.isValid)
                        {
                            readerState = State.FAILED;
                            return;
                        }
                    }

                    if (validate().isValid)
                    {
                        readerState = State.SUCCESS;
                    }
                    else
                    {
                        readerState = State.FAILED;
                    }
                }
                else
                {
                    readerState = State.FAILED;
                }
                break;
            default:
                // Do nothing in SUCCESS or FAILED states
                break;
        }
    }

    /**
     * NFC Transport Profile 2.0.1 &sect;6.1: the SELECT response data <em>MUST contain</em> tag
     * {@code 5C} carrying protocol version {@code 01 00}. The spec says "contain", not "equal",
     * so additional or reordered TLVs are permitted and this parses rather than byte-compares.
     *
     * <p>A success status word with no response data identifies an EV Profile card
     * (&sect;9.1) and is rejected here: this reader accepts the SE V1 / SE V2 card
     * profiles only.</p>
     */
    static boolean isAcceptedSelectResponse(byte[] response)
    {
        if (response == null || response.length < 2)
        {
            return false;
        }
        if (response[response.length - 2] != SUCCESS_STATUS[0]
                || response[response.length - 1] != SUCCESS_STATUS[1])
        {
            return false;
        }

        byte[] data = Arrays.copyOfRange(response, 0, response.length - 2);
        if (data.length == 0)
        {
            return false; // EV Profile card (no 5C version TLV) - not accepted by this reader
        }

        byte[] expected = Hex.decode(SUPPORTED_PROTOCOL_VERSION);
        byte[] version = findTlvValue(data, NFC_PacketType.ProtocolVersion.getType() & 0xFF);
        return version != null && Arrays.areEqual(version, expected);
    }

    /**
     * Scan top-level BER-TLV objects and return the value of the first one matching
     * {@code wantTag}, ignoring any unrecognized objects. Supports one- and two-byte tags
     * and short-form plus {@code 81} / {@code 82} long-form lengths.
     */
    private static byte[] findTlvValue(byte[] b, int wantTag)
    {
        int i = 0;
        while (i < b.length)
        {
            int first = b[i] & 0xFF;
            int tag;
            int off;
            if ((first & 0x1F) == 0x1F)
            {
                if (i + 1 >= b.length)
                {
                    return null;
                }
                tag = (first << 8) | (b[i + 1] & 0xFF);
                off = i + 2;
            }
            else
            {
                tag = first;
                off = i + 1;
            }

            if (off >= b.length)
            {
                return null;
            }

            int lenFirst = b[off] & 0xFF;
            int len;
            int valStart;
            if (lenFirst < 0x80)
            {
                len = lenFirst;
                valStart = off + 1;
            }
            else if (lenFirst == 0x81)
            {
                if (off + 1 >= b.length)
                {
                    return null;
                }
                len = b[off + 1] & 0xFF;
                valStart = off + 2;
            }
            else if (lenFirst == 0x82)
            {
                if (off + 2 >= b.length)
                {
                    return null;
                }
                len = ((b[off + 1] & 0xFF) << 8) | (b[off + 2] & 0xFF);
                valStart = off + 3;
            }
            else
            {
                return null;
            }

            if (valStart + len > b.length)
            {
                return null;
            }
            if (tag == wantTag)
            {
                return Arrays.copyOfRange(b, valStart, valStart + len);
            }
            i = valStart + len;
        }
        return null;
    }

    @Override
    public ValidationResult validate()
    {
        if (!isDevice && currentMessage instanceof ReaderResponseMessage)
        {
            return new SuccessResult();
        }
        return super.validate();
    }

    public byte[] getCommandToWrite()
    {
        if (isDevice)
        {
            return null;
        }

        switch (readerState)
        {
            case INITIAL:
                return Hex.decode(SELECT_COMMAND_STRING);
            case AWAITING_AUTHENTICATION:
                byte[] data = toWrite();
                var prefix = Hex.decode(AUTHENTICATION_COMMAND_PREFIX_STRING);
                ByteBuffer command = ByteBuffer.allocate(data.length + prefix.length + 1);
                command.put(prefix);
                command.put((byte) data.length);
                command.put(data);
                return command.array();
            default:
                return null;
        }
    }

    public boolean isTransactionSuccessful()
    {
        if (isDevice)
        {
            return transactionSuccessful;
        }
        else
        {
            return readerState == State.SUCCESS;
        }
    }
}