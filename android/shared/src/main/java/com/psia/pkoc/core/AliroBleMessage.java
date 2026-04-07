package com.psia.pkoc.core;

import java.util.Arrays;

/**
 * Aliro BLE message framing helper (Table 11-10 of Aliro 1.0 spec).
 *
 * Message format:
 *   Protocol_Header (1 byte) | Message_ID (1 byte) | Length (2 bytes BE) | Payload (variable)
 *
 * Attribute format (Table 11-12):
 *   Attribute_ID (1 byte) | Attribute_Length (1 byte) | Attribute_Value (variable)
 */
public class AliroBleMessage
{
    // -------------------------------------------------------------------------
    // Protocol Types
    // -------------------------------------------------------------------------
    public static final int PROTOCOL_AP           = 0;
    public static final int PROTOCOL_UWB_RANGING  = 1;
    public static final int PROTOCOL_NOTIFICATION = 2;
    public static final int PROTOCOL_SUPPLEMENTARY = 3;
    public static final int PROTOCOL_THIRD_PARTY  = 4;

    // -------------------------------------------------------------------------
    // Message IDs for AP (Protocol Type = 0)
    // -------------------------------------------------------------------------
    public static final int AP_RQ = 0;
    public static final int AP_RS = 1;

    // -------------------------------------------------------------------------
    // Message IDs for Notification (Protocol Type = 2)
    // -------------------------------------------------------------------------
    public static final int NOTIF_EVENT                       = 0;
    public static final int NOTIF_RANGING                     = 1;
    public static final int NOTIF_READER_STATUS_CHANGED       = 2;
    public static final int NOTIF_READER_STATUS_COMPLETED     = 3;
    public static final int NOTIF_RKE_REQUEST                 = 4;
    public static final int NOTIF_INITIATE_AP                 = 5;
    public static final int NOTIF_INITIATE_AP_RKE             = 6;

    // -------------------------------------------------------------------------
    // Build a complete Aliro BLE message
    // -------------------------------------------------------------------------

    /**
     * Build an Aliro BLE message.
     *
     * @param protocolType Protocol_Header value (AP=0, NOTIFICATION=2, etc.)
     * @param messageId    Message_ID value
     * @param payload      Payload bytes (may be null or empty)
     * @return Complete message: header(1) | msgId(1) | length(2 BE) | payload
     */
    public static byte[] build(int protocolType, int messageId, byte[] payload)
    {
        int payloadLen = (payload != null) ? payload.length : 0;
        byte[] msg = new byte[4 + payloadLen];
        msg[0] = (byte) protocolType;
        msg[1] = (byte) messageId;
        msg[2] = (byte) ((payloadLen >> 8) & 0xFF);
        msg[3] = (byte) (payloadLen & 0xFF);
        if (payload != null && payloadLen > 0)
        {
            System.arraycopy(payload, 0, msg, 4, payloadLen);
        }
        return msg;
    }

    // -------------------------------------------------------------------------
    // Parse message header
    // -------------------------------------------------------------------------

    /**
     * Parse the 4-byte header from an Aliro BLE message.
     *
     * @param data Raw message bytes (at least 4 bytes)
     * @return int[3]: [protocolType, messageId, payloadLength], or null if too short
     */
    public static int[] parseHeader(byte[] data)
    {
        if (data == null || data.length < 4) return null;
        int protocolType = data[0] & 0xFF;
        int messageId    = data[1] & 0xFF;
        int payloadLen   = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
        return new int[]{ protocolType, messageId, payloadLen };
    }

    /**
     * Extract the payload from a complete Aliro BLE message.
     *
     * @param data Complete message bytes
     * @return Payload bytes, or null if message is malformed
     */
    public static byte[] extractPayload(byte[] data)
    {
        if (data == null || data.length < 4) return null;
        int payloadLen = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
        if (data.length < 4 + payloadLen) return null;
        return Arrays.copyOfRange(data, 4, 4 + payloadLen);
    }

    // -------------------------------------------------------------------------
    // Attribute helpers (Table 11-12)
    // -------------------------------------------------------------------------

    /**
     * Build an attribute: AttrID(1) | AttrLen(1) | AttrValue(variable).
     *
     * @param attrId Attribute ID byte
     * @param value  Attribute value bytes
     * @return Encoded attribute
     */
    public static byte[] buildAttribute(int attrId, byte[] value)
    {
        int valLen = (value != null) ? value.length : 0;
        byte[] attr = new byte[2 + valLen];
        attr[0] = (byte) attrId;
        attr[1] = (byte) valLen;
        if (value != null && valLen > 0)
        {
            System.arraycopy(value, 0, attr, 2, valLen);
        }
        return attr;
    }

    /**
     * Build a multi-attribute payload by concatenating multiple attributes.
     *
     * @param attributes Attribute byte arrays to concatenate
     * @return Concatenated payload
     */
    public static byte[] buildPayload(byte[]... attributes)
    {
        int totalLen = 0;
        for (byte[] attr : attributes) totalLen += attr.length;
        byte[] payload = new byte[totalLen];
        int pos = 0;
        for (byte[] attr : attributes)
        {
            System.arraycopy(attr, 0, payload, pos, attr.length);
            pos += attr.length;
        }
        return payload;
    }

    /**
     * Parse the first attribute from a payload.
     *
     * @param payload Attribute data
     * @param offset  Starting offset
     * @return int[2]: [attrId, attrLength] or null if insufficient data
     */
    public static int[] parseAttributeHeader(byte[] payload, int offset)
    {
        if (payload == null || offset + 2 > payload.length) return null;
        return new int[]{ payload[offset] & 0xFF, payload[offset + 1] & 0xFF };
    }

    /**
     * Extract attribute value from a payload.
     *
     * @param payload Attribute data
     * @param offset  Starting offset (at AttrID byte)
     * @return Attribute value bytes, or null if malformed
     */
    public static byte[] extractAttributeValue(byte[] payload, int offset)
    {
        if (payload == null || offset + 2 > payload.length) return null;
        int len = payload[offset + 1] & 0xFF;
        if (offset + 2 + len > payload.length) return null;
        return Arrays.copyOfRange(payload, offset + 2, offset + 2 + len);
    }
}
