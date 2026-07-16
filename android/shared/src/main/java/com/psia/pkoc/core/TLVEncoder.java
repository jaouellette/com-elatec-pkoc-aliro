package com.psia.pkoc.core;

/**
 * Adapter that abstracts the transport-specific bits:
 *  - how to turn a Type enum into its byte,
 *  - how to decode a byte back to the enum,
 *  - how to construct the concrete packet object for callers,
 *  - how the length field is encoded/decoded.
 *
 * <p>The default length codec is the legacy single-byte form, which the NFC
 * path keeps unchanged. The BLE codec overrides it with the BER-TLV long-form
 * length (0x00–0x7F single byte, 0x81 LL, 0x82 LL LL) required by the PKOC BLE
 * Transport Profile 2.0.1 §5.3. For any value shorter than 128 bytes both forms
 * are byte-identical, so only the certificate (TLV 0x10) and the encrypted-data
 * TLV (0x40) — the only objects that can exceed 127 bytes — change on the wire,
 * and both the reader and device use the same codec so they stay in lockstep.</p>
 */
public interface TLVEncoder<TType, TPacket>
{
    byte toByte(TType type);

    TType decode(byte typeByte);

    TPacket newPacket(TType type, byte[] value);

    /**
     * Encode the length field for a value of {@code length} bytes.
     * Default: legacy single byte (used by NFC).
     */
    default byte[] writeLength(int length)
    {
        return new byte[] { (byte) length };
    }

    /**
     * Read the length field beginning at {@code buffer[offset]}.
     * Default: legacy single byte (used by NFC).
     *
     * @return {@code [valueLength, lengthFieldByteCount]}, or {@code null} if the
     *         buffer is too short or the length field is malformed.
     */
    default int[] readLength(byte[] buffer, int offset)
    {
        if (buffer == null || offset >= buffer.length)
        {
            return null;
        }
        return new int[] { buffer[offset] & 0xFF, 1 };
    }
}
