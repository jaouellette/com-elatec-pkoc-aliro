package com.psia.pkoc.core;

/**
 * BLE packet type for TLV-encoded data
 */
public enum BLE_PacketType
{
    Void ((byte) 0x00),
    PublicKey ((byte) 0x01),
    CompressedTransientPublicKey ((byte) 0x02),
    DigitalSignature ((byte) 0x03),
    Response ((byte) 0x04),
    UncompressedTransientPublicKey ((byte) 0x07),
    LastUpdateTime ((byte) 0x09),
    ProtocolVersion ((byte) 0x0C),
    ReaderLocationIdentifier ((byte) 0x0D),
    SiteIdentifier ((byte) 0x0E),
    // PKOC BLE Transport Profile 2.0.1 §5.4 / §7.1: Site Issuer-signed Reader
    // Certificate binding a Reader Public Key to a Reader Location Identifier.
    // Present only on the per-reader (Validated) ECDHE path; a legacy reader
    // omits it and the device falls back to the shared-Site-Key path (App. B).
    ReaderCertificate ((byte) 0x10),
    EncryptedDataFollows ((byte) 0x40),
    ManufacturerSpecificData ((byte) 0x80);

    private final byte type;

    /**
     * Get type
     * @return packet type as a byte
     */
    public byte getType() { return type; }

    /**
     * Decode
     * @param data Single byte signalling type of packet
     * @return Packet type as an enum
     */
    public static BLE_PacketType decode (byte data)
    {
        for (int a = 0; a < BLE_PacketType.values().length; a++)
        {
            if (BLE_PacketType.values()[a].getType() == data)
            {
                return BLE_PacketType.values()[a];
            }
        }

        return Void;
    }

    /**
     * Parameterized constructor
     * @param typeValue Type value as a byte
     */
    BLE_PacketType (byte typeValue)
    {
        type = typeValue;
    }
}
