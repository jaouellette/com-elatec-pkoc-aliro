package com.psia.pkoc.core;

import android.util.Log;

import java.nio.charset.StandardCharsets;

/**
 * AliroMailbox — sample mailbox data factory and TLV parser.
 *
 * Aliro 1.0 §18 (Appendix) mailbox format — Table 18-1:
 *
 *   0x60  <total-len>               ; Container tag
 *     0x81  <index-len>             ; Index: list of (OUI[3] | Type[1] | Offset[2]) entries
 *       OUI[0] OUI[1] OUI[2]       ;   3-byte IEEE OUI
 *       Type[0]                    ;   1-byte vendor entry type
 *       Offset[0] Offset[1]        ;   2-byte big-endian offset into data section
 *       ...                        ;   (repeat for each entry)
 *     0x82  <data-len>             ; Data: vendor payload bytes, concatenated
 *       <data-entry-0>
 *       <data-entry-1>
 *       ...
 *
 * ELATEC OUI: 0x00 0x13 0x7D  (IEEE-registered; used here as sample placeholder)
 *
 * Two vendor data entries:
 *
 *   Entry 0 — Reader Configuration (Type = 0x01), 46 bytes at offset 0:
 *     5 bytes  ASCII firmware version "3.2.1"
 *    14 bytes  ASCII reader serial   "ELA-SEC-PC-001"
 *    25 bytes  ASCII access zone     "ELATEC HQ - Main Entrance"
 *     2 bytes  door ID (big-endian uint16) = 0x00 0x01 (door #1)
 *
 *   Entry 1 — Door Status (Type = 0x02), 9 bytes at offset 46:
 *     1 byte   lock state: 0x01 = locked
 *     1 byte   battery %:  0x62 = 98 %
 *     1 byte   temperature °C: 0x18 = 24 °C / 75 °F
 *     4 bytes  last-event unix timestamp (big-endian uint32) = 0x6818A480 = 2025-05-05 08:00:00 UTC
 *     2 bytes  total transactions today (big-endian uint16)  = 0x04 0xDF = 1,247
 *
 * Total data payload: 55 bytes.
 * Total mailbox size returned: 300 bytes (padded with 0x00).
 */
public class AliroMailbox
{
    private static final String TAG = "AliroMailbox";

    /** ELATEC IEEE OUI (placeholder — 00:13:7D is an ELATEC-registered prefix) */
    public static final byte[] ELATEC_OUI = { 0x00, 0x13, 0x7D };

    /** Entry type: Reader Configuration */
    public static final int TYPE_READER_CONFIG = 0x01;

    /** Entry type: Door Status */
    public static final int TYPE_DOOR_STATUS   = 0x02;

    /** Total mailbox buffer size in bytes.
     *  300 bytes to accommodate certification harness read patterns
     *  (reads at offset+len up to 300). */
    public static final int MAILBOX_SIZE       = 300;

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Build the 256-byte sample mailbox per Aliro §18 Table 18-1.
     *
     * Layout:
     *   [0]    0x60             — container tag
     *   [1]    <inner-len>      — length of everything after this byte
     *   [2]    0x81             — index tag
     *   [3]    <index-len>      — length of index data (2 entries × 6 bytes = 12)
     *   [4..9]   entry 0 index: OUI(3) + Type(1) + Offset(2)
     *   [10..15] entry 1 index: OUI(3) + Type(1) + Offset(2)
     *   [16]   0x82             — data tag
     *   [17]   <data-len>       — length of data section (52 bytes)
     *   [18..60]  entry 0 data  (43 bytes: Reader Configuration)
     *   [61..69]  entry 1 data  (9 bytes: Door Status)
     *   [70..255] zero padding
     *
     * @return 256-byte array; never null.
     */
    public static byte[] buildSampleMailbox()
    {
        byte[] mailbox = new byte[MAILBOX_SIZE]; // pre-zeroed

        // ---- Entry 0: Reader Configuration (46 bytes) ----
        // Firmware version:  "3.2.1"              — 5 bytes ASCII
        // Reader serial:     "ELA-SEC-PC-001"     — 14 bytes ASCII
        // Access zone:       "ELATEC HQ - Main Entrance" — 25 bytes ASCII
        // Door ID:           0x00 0x01 (door #1)  — 2 bytes
        byte[] fwVersion   = "3.2.1".getBytes(StandardCharsets.US_ASCII);               //  5 bytes
        byte[] serial      = "ELA-SEC-PC-001".getBytes(StandardCharsets.US_ASCII);      // 14 bytes
        byte[] zoneName    = "ELATEC HQ - Main Entrance".getBytes(StandardCharsets.US_ASCII); // 25 bytes
        byte[] doorId      = { 0x00, 0x01 };                                            //  2 bytes
        // Total: 5 + 14 + 25 + 2 = 46 bytes

        // Assemble entry 0 payload
        byte[] entry0 = new byte[fwVersion.length + serial.length + zoneName.length + doorId.length];
        int pos = 0;
        System.arraycopy(fwVersion,  0, entry0, pos, fwVersion.length);  pos += fwVersion.length;
        System.arraycopy(serial,     0, entry0, pos, serial.length);     pos += serial.length;
        System.arraycopy(zoneName,   0, entry0, pos, zoneName.length);   pos += zoneName.length;
        System.arraycopy(doorId,     0, entry0, pos, doorId.length);
        // entry0.length == 46

        // ---- Entry 1: Door Status (9 bytes) ----
        // lock state:  0x01 (locked)
        // battery:     0x62 (98 %)
        // temperature: 0x18 (24 °C / 75 °F) — Palm City FL ambient
        // last event:  0x6818A480 = 2025-05-05 08:00:00 UTC (big-endian uint32)
        // txn count:   0x04DF = 1,247 (big-endian uint16)
        long  lastEventTs   = 0x6818A480L; // 2025-05-05 08:00:00 UTC
        int   txnCount      = 0x04DF;      // 1,247
        byte[] entry1 = {
            0x01,                                     // lock state: locked
            0x62,                                     // battery: 98%
            0x18,                                     // temperature: 24°C / 75°F
            (byte)((lastEventTs >> 24) & 0xFF),       // timestamp MSB
            (byte)((lastEventTs >> 16) & 0xFF),
            (byte)((lastEventTs >>  8) & 0xFF),
            (byte)( lastEventTs        & 0xFF),       // timestamp LSB
            (byte)((txnCount   >>  8) & 0xFF),        // txn count MSB
            (byte)( txnCount          & 0xFF)         // txn count LSB
        };
        // entry1.length == 9

        // ---- Offsets within the data section ----
        int offset0 = 0;                   // entry 0 starts at byte 0 of data section
        int offset1 = entry0.length;       // entry 1 starts after entry 0 (offset = 46)

        // ---- Index: 2 entries × 6 bytes each = 12 bytes ----
        // Each index entry: OUI[3] | Type[1] | Offset[2 big-endian]
        byte[] indexData = new byte[12];
        // entry 0 index
        indexData[0] = ELATEC_OUI[0];
        indexData[1] = ELATEC_OUI[1];
        indexData[2] = ELATEC_OUI[2];
        indexData[3] = (byte) TYPE_READER_CONFIG;
        indexData[4] = (byte)((offset0 >> 8) & 0xFF);
        indexData[5] = (byte)( offset0        & 0xFF);
        // entry 1 index
        indexData[6]  = ELATEC_OUI[0];
        indexData[7]  = ELATEC_OUI[1];
        indexData[8]  = ELATEC_OUI[2];
        indexData[9]  = (byte) TYPE_DOOR_STATUS;
        indexData[10] = (byte)((offset1 >> 8) & 0xFF);
        indexData[11] = (byte)( offset1        & 0xFF);

        // ---- Data section: entry0 || entry1 ----
        int dataLen = entry0.length + entry1.length; // 46 + 9 = 55

        // ---- TLV framing ----
        // 0x82 tag + 1 byte len + dataLen bytes of data  = 2 + 55 = 57
        // 0x81 tag + 1 byte len + 12 bytes of index      = 2 + 12 = 14
        // inner content = 14 + 57 = 71
        // 0x60 tag + 1 byte len + 71                     = 2 + 71 = 73 bytes total used
        int innerLen = (2 + indexData.length) + (2 + dataLen);
        // innerLen = 71

        if (innerLen + 2 > MAILBOX_SIZE)
        {
            // Shouldn't happen with these sizes, but guard defensively
            Log.e(TAG, "buildSampleMailbox: data too large for mailbox buffer");
            return mailbox;
        }

        int i = 0;

        // Container tag
        mailbox[i++] = 0x60;
        mailbox[i++] = (byte)(innerLen & 0xFF);

        // Index TLV
        mailbox[i++] = (byte)0x81;
        mailbox[i++] = (byte)(indexData.length & 0xFF);
        System.arraycopy(indexData, 0, mailbox, i, indexData.length);
        i += indexData.length;

        // Data TLV
        mailbox[i++] = (byte)0x82;
        mailbox[i++] = (byte)(dataLen & 0xFF);
        System.arraycopy(entry0, 0, mailbox, i, entry0.length);
        i += entry0.length;
        System.arraycopy(entry1, 0, mailbox, i, entry1.length);
        // Remaining bytes are already 0x00 from array initialisation

        Log.d(TAG, "buildSampleMailbox: wrote " + (2 + innerLen)
                + " bytes (padded to " + MAILBOX_SIZE + ")");
        return mailbox;
    }

    // =========================================================================
    // TLV parser — used by HomeFragment display
    // =========================================================================

    /**
     * Parse a §18 mailbox buffer and return a human-readable multi-line string.
     *
     * The returned string uses the clean indented format expected by the Aliro
     * result screen.  Section headers are in ALL-CAPS (e.g. "Reader Config (OUI: …)")
     * so that displayPublicKeyInfo() can detect and bold them.
     *
     * Returns a generic hex-dump prefix on any parse error so the UI always
     * shows something meaningful.
     *
     * @param mailbox  Raw mailbox bytes as received from the credential
     * @param maxBytes Maximum number of bytes passed in (actual used slice)
     * @return Multi-line human-readable summary
     */
    public static String parseMailboxToString(byte[] mailbox, int maxBytes)
    {
        if (mailbox == null || maxBytes == 0)
            return "(empty)";

        try
        {
            int i = 0;

            // Must start with 0x60
            if ((mailbox[i] & 0xFF) != 0x60)
                return fallbackHex(mailbox, maxBytes);

            i++;
            int innerLen = mailbox[i++] & 0xFF;

            // Expect 0x81 next (index)
            if ((mailbox[i] & 0xFF) != 0x81)
                return fallbackHex(mailbox, maxBytes);
            i++;
            int indexLen = mailbox[i++] & 0xFF;
            int indexStart = i;
            i += indexLen;

            // Expect 0x82 next (data)
            if ((mailbox[i] & 0xFF) != 0x82)
                return fallbackHex(mailbox, maxBytes);
            i++;
            int dataLen = mailbox[i++] & 0xFF;
            int dataStart = i;

            // Parse index entries (each = 6 bytes: OUI[3] + Type[1] + Offset[2])
            int numEntries = indexLen / 6;
            StringBuilder sb = new StringBuilder();

            for (int e = 0; e < numEntries; e++)
            {
                int base = indexStart + e * 6;
                int oui0 = mailbox[base]     & 0xFF;
                int oui1 = mailbox[base + 1] & 0xFF;
                int oui2 = mailbox[base + 2] & 0xFF;
                int type = mailbox[base + 3] & 0xFF;
                int off  = ((mailbox[base + 4] & 0xFF) << 8) | (mailbox[base + 5] & 0xFF);

                // Attempt field-level decode for known ELATEC entries
                if (oui0 == (ELATEC_OUI[0] & 0xFF)
                        && oui1 == (ELATEC_OUI[1] & 0xFF)
                        && oui2 == (ELATEC_OUI[2] & 0xFF))
                {
                    sb.append(decodeElatecEntry(type, oui0, oui1, oui2,
                            mailbox, dataStart + off, dataLen - off));
                }
                else
                {
                    sb.append(String.format("  Unknown Entry (OUI: %02X:%02X:%02X, Type: 0x%02X)\n",
                            oui0, oui1, oui2, type));
                }
            }

            return sb.toString().trim();
        }
        catch (Exception ex)
        {
            return fallbackHex(mailbox, maxBytes);
        }
    }

    /**
     * Decode a known ELATEC vendor entry into a human-readable block.
     *
     * Type 0x01 = Reader Configuration (43-byte fixed layout)
     * Type 0x02 = Door Status (9-byte fixed layout)
     */
    private static String decodeElatecEntry(int type, int oui0, int oui1, int oui2,
                                             byte[] buf, int start, int remaining)
    {
        StringBuilder sb = new StringBuilder();
        String ouiStr = String.format("%02X:%02X:%02X", oui0, oui1, oui2);
        try
        {
            switch (type)
            {
                case TYPE_READER_CONFIG:
                {
                    // 5 bytes firmware, 14 bytes serial, 25 bytes zone, 2 bytes door ID
                    sb.append("  Reader Config (OUI: ").append(ouiStr).append(")\n");
                    if (remaining < 46) { sb.append("    [truncated]\n"); break; }
                    String fw   = new String(buf, start,      5,  StandardCharsets.US_ASCII).trim();
                    String ser  = new String(buf, start + 5,  14, StandardCharsets.US_ASCII).trim();
                    String zone = new String(buf, start + 19, 25, StandardCharsets.US_ASCII).trim();
                    int doorId  = ((buf[start + 44] & 0xFF) << 8) | (buf[start + 45] & 0xFF);
                    sb.append("    Firmware:     ").append(fw).append("\n");
                    sb.append("    Serial:       ").append(ser).append("\n");
                    sb.append("    Zone:         ").append(zone).append("\n");
                    sb.append(String.format("    Door ID:      #%d\n", doorId));
                    break;
                }
                case TYPE_DOOR_STATUS:
                {
                    // 1 lock + 1 battery + 1 temp + 4 timestamp + 2 txn count = 9
                    sb.append("  Door Status (OUI: ").append(ouiStr).append(")\n");
                    if (remaining < 9) { sb.append("    [truncated]\n"); break; }
                    int  lockState = buf[start]     & 0xFF;
                    int  battery   = buf[start + 1] & 0xFF;
                    int  tempC     = buf[start + 2] & 0xFF;
                    long ts = ((long)(buf[start + 3] & 0xFF) << 24)
                            | ((long)(buf[start + 4] & 0xFF) << 16)
                            | ((long)(buf[start + 5] & 0xFF) <<  8)
                            |  (long)(buf[start + 6] & 0xFF);
                    int  txnCount  = ((buf[start + 7] & 0xFF) << 8) | (buf[start + 8] & 0xFF);
                    String lockStr = (lockState == 0x01) ? "Locked"
                                  : (lockState == 0x00) ? "Unlocked"
                                  : String.format("0x%02X", lockState);
                    sb.append("    Lock:         ").append(lockStr).append("\n");
                    sb.append(String.format("    Battery:      %d%%\n", battery));
                    int tempF = (int) Math.round(tempC * 9.0 / 5.0 + 32);
                    sb.append(String.format("    Temperature:  %d\u00b0C / %d\u00b0F\n", tempC, tempF));
                    sb.append(String.format("    Transactions: %d\n", txnCount));
                    break;
                }
                default:
                    sb.append(String.format("  Unknown Entry (OUI: %s, Type: 0x%02X, %d bytes)\n",
                            ouiStr, type, remaining));
                    break;
            }
        }
        catch (Exception e)
        {
            sb.append("    [parse error: ").append(e.getMessage()).append("]\n");
        }
        return sb.toString();
    }

    /** Produce a short hex preview string for unrecognised / malformed mailbox data */
    private static String fallbackHex(byte[] data, int len)
    {
        int show = Math.min(len, 32);
        StringBuilder sb = new StringBuilder("Raw ");
        sb.append(len).append("B: ");
        for (int i = 0; i < show; i++)
            sb.append(String.format("%02X", data[i] & 0xFF));
        if (len > show) sb.append("…");
        return sb.toString();
    }
}
