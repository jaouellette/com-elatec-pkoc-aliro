package com.psia.pkoc.core;

import static java.lang.System.arraycopy;

import android.util.Log;

import org.bouncycastle.util.Arrays;

import java.util.ArrayList;

/**
 * Type Length Value Provider.
 *
 * <p>The BLE codec uses BER-TLV long-form lengths (PKOC BLE Transport Profile
 * 2.0.1 §5.3); the NFC codec keeps the legacy single-byte length via the
 * {@link TLVEncoder} defaults so the NFC wire format is unchanged.</p>
 */
public class TLVProvider
{
    public static byte[] GetBleTLV(BLE_PacketType type, byte[] value)
    {
        return getTLV(type, value, BLE_CODEC);
    }

    public static BLE_Packet GetBleValue(byte[] encoded)
    {
        return getValue(encoded, BLE_CODEC);
    }

    public static ArrayList<BLE_Packet> GetBleValues(byte[] buffer)
    {
        return getValues(buffer, BLE_CODEC);
    }

    public static byte[] GetNfcTLV(NFC_PacketType type, byte[] value)
    {
        return getTLV(type, value, NFC_CODEC);
    }

    public static NFC_Packet GetNfcValue(byte[] encoded)
    {
        return getValue(encoded, NFC_CODEC);
    }

    public static ArrayList<NFC_Packet> GetNfcValues(byte[] buffer)
    {
        return getValues(buffer, NFC_CODEC);
    }

    private static final TLVEncoder<BLE_PacketType, BLE_Packet> BLE_CODEC = new TLVEncoder<BLE_PacketType, BLE_Packet>()
    {
        @Override
        public byte toByte(BLE_PacketType type)
        {
            return type.getType();
        }

        @Override
        public BLE_PacketType decode(byte typeByte)
        {
            return BLE_PacketType.decode(typeByte);
        }

        @Override
        public BLE_Packet newPacket(BLE_PacketType type, byte[] value)
        {
            return new BLE_Packet(type, value);
        }

        // --- BER-TLV long-form length (PKOC BLE Transport Profile 2.0.1 §5.3) ---

        @Override
        public byte[] writeLength(int length)
        {
            if (length < 0x80)
            {
                return new byte[] { (byte) length };
            }
            if (length < 0x100)
            {
                return new byte[] { (byte) 0x81, (byte) length };
            }
            return new byte[] { (byte) 0x82, (byte) ((length >> 8) & 0xFF), (byte) (length & 0xFF) };
        }

        @Override
        public int[] readLength(byte[] buffer, int offset)
        {
            if (buffer == null || offset >= buffer.length)
            {
                return null;
            }
            int first = buffer[offset] & 0xFF;
            if (first < 0x80)
            {
                return new int[] { first, 1 };
            }
            if (first == 0x81)
            {
                if (offset + 1 >= buffer.length) return null;
                return new int[] { buffer[offset + 1] & 0xFF, 2 };
            }
            if (first == 0x82)
            {
                if (offset + 2 >= buffer.length) return null;
                int len = ((buffer[offset + 1] & 0xFF) << 8) | (buffer[offset + 2] & 0xFF);
                return new int[] { len, 3 };
            }
            // 0x83+ (values >= 16 MiB) are not used by PKOC BLE.
            Log.w("TLVProvider", "Unsupported BLE length form: 0x" + Integer.toHexString(first));
            return null;
        }
    };

    private static final TLVEncoder<NFC_PacketType, NFC_Packet> NFC_CODEC = new TLVEncoder<NFC_PacketType, NFC_Packet>()
    {
        @Override
        public byte toByte(NFC_PacketType type)
        {
            return type.getType();
        }

        @Override
        public NFC_PacketType decode(byte typeByte)
        {
            return NFC_PacketType.decode(typeByte);
        }

        @Override
        public NFC_Packet newPacket(NFC_PacketType type, byte[] value)
        {
            return new NFC_Packet(type, value);
        }
        // NFC keeps the legacy single-byte length via the TLVEncoder defaults.
    };

    /**
     * Get Type Length Value encoded byte array
     * @param type Message type
     * @param data Message content
     * @return TLV encoded byte array
     */
    private static <TType, TPacket> byte[] getTLV(TType type, byte[] data, TLVEncoder<TType, TPacket> codec)
    {
        byte[] lengthField = codec.writeLength(data.length);
        byte[] prepend = new byte[1 + lengthField.length];
        prepend[0] = codec.toByte(type);
        System.arraycopy(lengthField, 0, prepend, 1, lengthField.length);
        return Arrays.concatenate(prepend, data);
    }

    /**
     * Get Value of encoded Type Length Value message
     * @param encodedData TLV encoded byte array
     * @return packet containing type and decoded byte array
     */
    private static <TType, TPacket> TPacket getValue(byte[] encodedData, TLVEncoder<TType, TPacket> codec)
    {
        if (encodedData == null || encodedData.length < 2) // not long enough to be a TLV
        {
            return null;
        }

        TType packetType = codec.decode(encodedData[0]);

        int[] lengthRead = codec.readLength(encodedData, 1);
        if (lengthRead == null)
        {
            Log.e("TLVProvider", "Malformed length field");
            return null;
        }
        int length = lengthRead[0];
        int headerLength = 1 + lengthRead[1];

        Log.d("TLVProvider", "Processing TLV: Type=" + packetType + ", Length=" + length);

        if (packetType == BLE_PacketType.Void)
        {
            Log.d("TLVProvider", "Skipping Void packet");
            return null;
        }

        if (length > encodedData.length - headerLength)
        {
            Log.e("TLVProvider", "Invalid length: " + length + " for data: " + java.util.Arrays.toString(encodedData));
            return null;
        }

        byte[] decodedData = new byte[length];
        System.arraycopy(encodedData, headerLength, decodedData, 0, length);

        Log.d("TLVProvider", "Decoded data: " + java.util.Arrays.toString(decodedData));

        return codec.newPacket(packetType, decodedData);
    }

    /**
     * Get values of a message containing TLV encoded data
     * @param buffer byte array containing one or more TLV encoded messages
     * @return Array list of messages to be read
     */
    private static <TType, TPacket> ArrayList<TPacket> getValues(byte[] buffer, TLVEncoder<TType, TPacket> codec)
    {
        ArrayList<TPacket> packets = new ArrayList<>();
        if (buffer == null || buffer.length == 0)
        {
            return packets;
        }

        int cursor = 0;
        while (cursor + 1 <= buffer.length) // at least a Type byte remains
        {
            int start = cursor;

            byte typeByte = buffer[cursor++];

            int[] lengthRead = codec.readLength(buffer, cursor);
            if (lengthRead == null)
            {
                Log.w("TLVProvider", "Could not read TLV length at offset " + cursor + "; aborting.");
                break;
            }
            int length = lengthRead[0];
            cursor += lengthRead[1];

            // If not enough bytes remain for the value, stop parsing (graceful fail for trailing noise)
            if (cursor + length > buffer.length)
            {
                Log.w("TLVProvider", "Remaining buffer smaller than TLV length. aborting. start=" + start + " length=" + length + " remaining=" + (buffer.length - cursor));
                break;
            }

            // Slice out the value bytes
            byte[] value = new byte[length];
            if (length > 0)
            {
                arraycopy(buffer, cursor, value, 0, length);
            }
            cursor += length;

            // Build packet and append
            TType type = codec.decode(typeByte);
            packets.add(codec.newPacket(type, value));
        }

        return packets;
    }
}
