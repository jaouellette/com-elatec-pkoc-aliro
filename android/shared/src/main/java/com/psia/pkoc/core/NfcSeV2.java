package com.psia.pkoc.core;

import androidx.annotation.Nullable;

import java.util.Arrays;

/**
 * PKOC SE V2 Profile command/response helpers (NFC Transport Profile 2.0.1 §6.2, §8).
 *
 * <p>Static builders and parsers for GET DATA (INFO), GET DATA (PKOC-CVC), and
 * INTERNAL AUTHENTICATE, usable from both the Card (HCE) and Reader sides. SE V1
 * (SELECT + AUTHENTICATE) is unchanged and lives in the existing NFC transaction.</p>
 */
public final class NfcSeV2
{
    private NfcSeV2() { }

    // --- Status words ---
    public static final byte[] SW_SUCCESS          = { (byte) 0x90, 0x00 };
    public static final byte[] SW_WRONG_LENGTH     = { (byte) 0x67, 0x00 };
    public static final byte[] SW_COND_NOT_SAT     = { (byte) 0x69, (byte) 0x85 };
    public static final byte[] SW_INCORRECT_P1P2   = { (byte) 0x6A, (byte) 0x86 };
    public static final byte[] SW_REF_DATA_NOT_FND = { (byte) 0x6A, (byte) 0x88 };
    public static final byte[] SW_INS_NOT_SUPPORTED= { (byte) 0x6D, 0x00 };
    public static final byte[] SW_GENERAL_ERROR    = { (byte) 0x6F, 0x00 };

    // --- Reader → Card command APDUs (§6.2, §8) ---
    public static final byte[] SELECT_APDU        = hex("00A4040008A000000898000001" + "00");
    public static final byte[] GET_DATA_INFO_APDU = hex("00CA7F6300");   // tag 7F63
    public static final byte[] GET_DATA_CVC_APDU  = hex("00CA7F2100");   // tag 7F21

    // --- Tags ---
    private static final int TAG_INFO_7F63 = 0x7F63;
    private static final int TAG_INFO_5C   = 0x5C;
    private static final int TAG_CVC_7F21  = 0x7F21;
    private static final int TAG_SIG_9E    = 0x9E;

    /** The SE V2 capability marker value carried in the INFO response (§6.2). */
    public static final byte[] SE_V2_MARKER = { 0x02, 0x00 };

    // ================================================================
    // Card (HCE) side — build responses
    // ================================================================

    /** GET DATA (INFO) response: {@code 7F63 04 5C 02 02 00} + 9000 (§6.2). */
    public static byte[] buildInfoResponse()
    {
        byte[] inner = tlv(TAG_INFO_5C, SE_V2_MARKER);          // 5C 02 02 00
        byte[] obj   = tlv(TAG_INFO_7F63, inner);               // 7F63 04 5C 02 02 00
        return concat(obj, SW_SUCCESS);
    }

    /** GET DATA (PKOC-CVC) response: the full {@code 7F21} certificate + 9000 (§8.1). */
    public static byte[] buildCvcResponse(byte[] cvc7F21)
    {
        return concat(cvc7F21, SW_SUCCESS);
    }

    /** INTERNAL AUTHENTICATE response: {@code 9E <len> <signature>} + 9000 (§8.2). */
    public static byte[] buildInternalAuthResponse(byte[] signature)
    {
        return concat(tlv(TAG_SIG_9E, signature), SW_SUCCESS);
    }

    // ================================================================
    // Card (HCE) side — classify inbound APDUs
    // ================================================================

    public static boolean isSelect(byte[] apdu)        { return startsWith(apdu, hex("00A4040008A000000898000001")); }
    public static boolean isGetDataInfo(byte[] apdu)   { return startsWith(apdu, hex("00CA7F63")); }
    public static boolean isGetDataCvc(byte[] apdu)    { return startsWith(apdu, hex("00CA7F21")); }
    public static boolean isInternalAuth(byte[] apdu)  { return startsWith(apdu, hex("00880000")); }

    /** Extract the 32-byte challenge from an INTERNAL AUTHENTICATE APDU (§8.2), or {@code null}. */
    @Nullable
    public static byte[] extractInternalAuthChallenge(byte[] apdu)
    {
        // 00 88 00 00 Lc <challenge> [Le]
        if (apdu == null || apdu.length < 6) return null;
        int lc = apdu[4] & 0xFF;
        if (lc == 0 || apdu.length < 5 + lc) return null;
        return Arrays.copyOfRange(apdu, 5, 5 + lc);
    }

    // ================================================================
    // Reader side — build commands / parse responses
    // ================================================================

    /** Build the INTERNAL AUTHENTICATE command for a 32-byte challenge (§8.2). */
    public static byte[] buildInternalAuthCommand(byte[] challenge32)
    {
        // 00 88 00 00 Lc <challenge> 00
        byte[] header = hex("00880000");
        byte[] out = new byte[header.length + 1 + challenge32.length + 1];
        System.arraycopy(header, 0, out, 0, header.length);
        out[header.length] = (byte) challenge32.length;
        System.arraycopy(challenge32, 0, out, header.length + 1, challenge32.length);
        out[out.length - 1] = 0x00; // Le
        return out;
    }

    /** GET RESPONSE for response chaining ({@code 61 XX}); §8.1. */
    public static byte[] buildGetResponse(int le)
    {
        return new byte[] { 0x00, (byte) 0xC0, 0x00, 0x00, (byte) (le & 0xFF) };
    }

    /** True if the status word of {@code resp} is {@code 61 XX} (more data available). */
    public static boolean isMoreData(byte[] resp)
    {
        return resp != null && resp.length >= 2 && (resp[resp.length - 2] & 0xFF) == 0x61;
    }

    /** The XX byte from a {@code 61 XX} status word (remaining length hint). */
    public static int moreDataLength(byte[] resp)
    {
        return (resp == null || resp.length < 1) ? 0 : (resp[resp.length - 1] & 0xFF);
    }

    /** True if the response ends in {@code 90 00}. */
    public static boolean isSuccess(byte[] resp)
    {
        return resp != null && resp.length >= 2
                && (resp[resp.length - 2] & 0xFF) == 0x90 && (resp[resp.length - 1] & 0xFF) == 0x00;
    }

    /** Strip a trailing 2-byte status word, returning just the data. */
    public static byte[] stripStatusWord(byte[] resp)
    {
        if (resp == null || resp.length < 2) return new byte[0];
        return Arrays.copyOfRange(resp, 0, resp.length - 2);
    }

    /**
     * Parse a GET DATA (INFO) response and report whether it marks an SE V2 card,
     * i.e. contains {@code 7F63 → 5C → 02 00} (§6.2). Unrecognized elements ignored.
     */
    public static boolean parseInfoIsSeV2(byte[] resp)
    {
        byte[] data = stripStatusWord(resp);
        byte[] info = valueOfTag(data, TAG_INFO_7F63);
        if (info == null) return false;
        byte[] marker = valueOfTag(info, TAG_INFO_5C);
        return marker != null && Arrays.equals(marker, SE_V2_MARKER);
    }

    /** Extract the {@code 7F21} CVC bytes from a GET DATA (PKOC-CVC) response (§8.1). */
    @Nullable
    public static byte[] extractCvc(byte[] resp)
    {
        byte[] data = stripStatusWord(resp);
        // Return the whole 7F21 TLV (tag..value), which PkocCvc.parse accepts directly.
        int[] t = readTag(data, 0);
        if (t == null || t[0] != TAG_CVC_7F21) return null;
        return data.clone();
    }

    /** Extract the signature (tag {@code 9E} value) from an INTERNAL AUTHENTICATE response (§8.2). */
    @Nullable
    public static byte[] extractInternalAuthSignature(byte[] resp)
    {
        byte[] data = stripStatusWord(resp);
        return valueOfTag(data, TAG_SIG_9E);
    }

    // ================================================================
    // Minimal TLV helpers (self-contained; BLE codec is unaffected)
    // ================================================================

    /** Find the value of the first top-level TLV whose tag matches {@code wantTag}. */
    @Nullable
    private static byte[] valueOfTag(byte[] b, int wantTag)
    {
        int i = 0;
        while (i < b.length)
        {
            int[] t = readTag(b, i);
            if (t == null) return null;
            int tag = t[0];
            int[] l = readLen(b, t[1]);
            if (l == null) return null;
            int len = l[0];
            int valStart = l[1];
            if (valStart + len > b.length) return null;
            if (tag == wantTag) return Arrays.copyOfRange(b, valStart, valStart + len);
            i = valStart + len;
        }
        return null;
    }

    @Nullable
    private static int[] readTag(byte[] b, int off)
    {
        if (off >= b.length) return null;
        int first = b[off] & 0xFF;
        if ((first & 0x1F) == 0x1F)
        {
            if (off + 1 >= b.length) return null;
            return new int[] { (first << 8) | (b[off + 1] & 0xFF), off + 2 };
        }
        return new int[] { first, off + 1 };
    }

    @Nullable
    private static int[] readLen(byte[] b, int off)
    {
        if (off >= b.length) return null;
        int first = b[off] & 0xFF;
        if (first < 0x80) return new int[] { first, off + 1 };
        if (first == 0x81) { if (off + 1 >= b.length) return null; return new int[] { b[off + 1] & 0xFF, off + 2 }; }
        if (first == 0x82) { if (off + 2 >= b.length) return null; return new int[] { ((b[off + 1] & 0xFF) << 8) | (b[off + 2] & 0xFF), off + 3 }; }
        return null;
    }

    private static byte[] tlv(int tag, byte[] value)
    {
        byte[] tagBytes = (tag > 0xFF) ? new byte[] { (byte) (tag >> 8), (byte) tag } : new byte[] { (byte) tag };
        byte[] lenBytes;
        int n = value.length;
        if (n < 0x80)       lenBytes = new byte[] { (byte) n };
        else if (n < 0x100) lenBytes = new byte[] { (byte) 0x81, (byte) n };
        else                lenBytes = new byte[] { (byte) 0x82, (byte) (n >> 8), (byte) n };
        return concat(tagBytes, lenBytes, value);
    }

    private static boolean startsWith(byte[] b, byte[] prefix)
    {
        if (b == null || b.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) if (b[i] != prefix[i]) return false;
        return true;
    }

    private static byte[] concat(byte[]... parts)
    {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, pos, p.length); pos += p.length; }
        return out;
    }

    private static byte[] hex(String s)
    {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
}
