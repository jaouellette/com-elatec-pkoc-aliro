package com.psia.pkoc;

import android.content.Context;
import android.content.Intent;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import com.psia.pkoc.core.LeafVerifiedManager;

import java.util.Arrays;

/**
 * HCE service that simulates a LEAF Verified credential (Open ID — Path 1).
 *
 * Emulates the MIFARE DUOX / DESFire EV3 APDU interface as described in the
 * LEAF Verified Tech Spec (leaf_verified.h reference).
 *
 * Protocol flow:
 *   Reader → SELECT (AID D2 76 00 00 85 01 01)   → 9000
 *   Reader → SELECT EF (file 00 01)               → 9000
 *   Reader → READ BINARY (offset, length)         → cert_chunk + 9000 / 6282
 *   Reader → INTERNAL AUTHENTICATE (32-byte nonce)→ DER sig + 9000
 *
 * AID is registered via {@code @xml/leaf_apduservice} in the manifest.
 */
public class LeafVerifiedHceService extends HostApduService
{
    private static final String TAG = "LeafVerifiedHceSvc";

    /** Broadcast action sent to SendCredentialFragment after successful INTERNAL AUTHENTICATE. */
    public static final String ACTION_LEAF_CREDENTIAL_SENT = "com.psia.pkoc.LEAF_CREDENTIAL_SENT";

    // -----------------------------------------------------------------------
    // Status words
    // -----------------------------------------------------------------------
    private static final byte[] SW_9000        = { (byte)0x90, 0x00 };
    private static final byte[] SW_6A80        = { (byte)0x6A, (byte)0x80 }; // wrong data
    private static final byte[] SW_6A82        = { (byte)0x6A, (byte)0x82 }; // file not found
    private static final byte[] SW_6A86        = { (byte)0x6A, (byte)0x86 }; // incorrect P1/P2
    private static final byte[] SW_6282        = { (byte)0x62, (byte)0x82 }; // end of file
    private static final byte[] SW_6985        = { (byte)0x69, (byte)0x85 }; // conditions not satisfied
    private static final byte[] SW_6D00        = { (byte)0x6D, 0x00 };       // INS not supported
    private static final byte[] SW_6E00        = { (byte)0x6E, 0x00 };       // CLA not supported
    private static final byte[] SW_6F00        = { (byte)0x6F, 0x00 };       // unknown error

    // APDU INS bytes
    private static final byte INS_SELECT             = (byte)0xA4;
    private static final byte INS_READ_BINARY        = (byte)0xB0;
    private static final byte INS_INTERNAL_AUTH      = (byte)0x88;

    // SELECT P1 values
    private static final byte P1_SELECT_BY_AID       = 0x04;
    private static final byte P1_SELECT_BY_EF        = 0x02;

    // READ BINARY chunk size used by the LEAF reader
    private static final int  CHUNK_SIZE              = 224;

    // -----------------------------------------------------------------------
    // State machine
    // -----------------------------------------------------------------------
    private static final int STATE_IDLE             = 0;  // waiting for SELECT AID
    private static final int STATE_SELECTED         = 1;  // AID selected, waiting for SELECT EF
    private static final int STATE_FILE_SELECTED    = 2;  // EF selected, waiting for READ BINARY
    private static final int STATE_READY_FOR_AUTH   = 3;  // cert fully read, waiting for INT AUTH

    private int    mState     = STATE_IDLE;

    // Cached cert and private key — loaded on first SELECT to avoid blocking
    private byte[] mCertDER   = null;
    private byte[] mCredPriv32 = null;

    // -----------------------------------------------------------------------
    // HostApduService
    // -----------------------------------------------------------------------

    @Override
    public void onDeactivated(int reason)
    {
        Log.d(TAG, "onDeactivated reason=" + reason);
        resetState();
    }

    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras)
    {
        if (apdu == null || apdu.length < 4)
        {
            Log.w(TAG, "processCommandApdu: apdu too short");
            return SW_6F00;
        }

        byte cla = apdu[0];
        byte ins = apdu[1];
        byte p1  = apdu[2];
        byte p2  = apdu[3];

        Log.d(TAG, "APDU CLA=" + String.format("%02X", cla & 0xFF)
                + " INS=" + String.format("%02X", ins & 0xFF)
                + " P1=" + String.format("%02X", p1 & 0xFF)
                + " P2=" + String.format("%02X", p2 & 0xFF)
                + " len=" + apdu.length);

        // Dispatch on INS
        switch (ins)
        {
            case INS_SELECT:
                return handleSelect(apdu, p1);

            case INS_READ_BINARY:
                return handleReadBinary(apdu, p1, p2);

            case INS_INTERNAL_AUTH:
                return handleInternalAuthenticate(apdu);

            default:
                Log.w(TAG, "Unknown INS: " + String.format("%02X", ins & 0xFF));
                return SW_6D00;
        }
    }

    // -----------------------------------------------------------------------
    // SELECT
    // -----------------------------------------------------------------------

    private byte[] handleSelect(byte[] apdu, byte p1)
    {
        if (p1 == P1_SELECT_BY_AID)
        {
            return handleSelectByAid(apdu);
        }
        else if (p1 == P1_SELECT_BY_EF)
        {
            return handleSelectEF(apdu);
        }
        else
        {
            // P1 not 0x04 (AID) or 0x02 (EF) — reject per ISO 7816-4
            Log.w(TAG, "SELECT with unsupported P1=" + String.format("%02X", p1));
            return SW_6A86;
        }
    }

    private byte[] handleSelectByAid(byte[] apdu)
    {
        // Parse Lc and AID data
        if (apdu.length < 5)
            return SW_6A82;

        int lc = apdu[4] & 0xFF;
        if (apdu.length < 5 + lc)
            return SW_6A80;

        byte[] aidReceived = Arrays.copyOfRange(apdu, 5, 5 + lc);
        byte[] leafAid     = LeafVerifiedManager.LEAF_OPEN_APP_AID;

        if (!Arrays.equals(aidReceived, leafAid))
        {
            Log.w(TAG, "SELECT AID mismatch: "
                    + bytesToHex(aidReceived) + " vs " + bytesToHex(leafAid));
            return SW_6A82;
        }

        // Load credential material
        if (!loadCredentialData())
        {
            Log.e(TAG, "handleSelectByAid: credential not provisioned");
            return SW_6985; // conditions not satisfied
        }

        mState = STATE_SELECTED;
        Log.d(TAG, "LEAF AID selected — state=SELECTED");

        // Respond with FCI: 6F <len> 84 <aidLen> <AID> A5 00 9000
        byte[] fci = buildFCI(leafAid);
        return appendSW(fci, SW_9000);
    }

    private byte[] handleSelectEF(byte[] apdu)
    {
        if (mState == STATE_IDLE)
        {
            Log.w(TAG, "SELECT EF received before SELECT AID");
            return SW_6985;
        }

        // Parse file ID from data field
        int lc = (apdu.length > 4) ? (apdu[4] & 0xFF) : 0;
        if (lc >= 2 && apdu.length >= 7)
        {
            byte[] fileId = { apdu[5], apdu[6] };
            if (!Arrays.equals(fileId, LeafVerifiedManager.LEAF_CERT_FILE_ID))
            {
                Log.w(TAG, "SELECT EF unknown file: " + bytesToHex(fileId));
                return SW_6A82;
            }
        }
        // Accept any EF select — we only have one file

        mState = STATE_FILE_SELECTED;
        Log.d(TAG, "EF selected — state=FILE_SELECTED, certLen=" + (mCertDER != null ? mCertDER.length : 0));
        return SW_9000;
    }

    // -----------------------------------------------------------------------
    // READ BINARY
    // -----------------------------------------------------------------------

    private byte[] handleReadBinary(byte[] apdu, byte p1, byte p2)
    {
        if (mState == STATE_IDLE || mState == STATE_SELECTED)
        {
            Log.w(TAG, "READ BINARY before file selected");
            return SW_6985;
        }
        if (mCertDER == null)
        {
            Log.e(TAG, "READ BINARY: cert is null");
            return SW_6F00;
        }

        // Offset from P1:P2 (big-endian 15-bit for short-form)
        int offset = ((p1 & 0x7F) << 8) | (p2 & 0xFF);

        // Le (requested length) — last byte of APDU or default
        int le;
        if (apdu.length == 4)
        {
            // No Le — return all remaining bytes
            le = mCertDER.length - offset;
        }
        else if (apdu.length == 5)
        {
            le = apdu[4] & 0xFF;
            if (le == 0) le = 256; // Le=0x00 means 256 in short form
        }
        else
        {
            le = apdu[apdu.length - 1] & 0xFF;
            if (le == 0) le = 256;
        }

        if (offset >= mCertDER.length)
        {
            // Past end of file
            return SW_6282;
        }

        int available = mCertDER.length - offset;
        boolean isLastChunk = (le >= available);
        int readLen = isLastChunk ? available : le;

        byte[] chunk = Arrays.copyOfRange(mCertDER, offset, offset + readLen);
        Log.d(TAG, "READ BINARY offset=" + offset + " le=" + le
                + " returned=" + readLen + " last=" + isLastChunk);

        // Advance state: once we have read past end, reader can authenticate
        if (isLastChunk)
            mState = STATE_READY_FOR_AUTH;

        return appendSW(chunk, isLastChunk ? SW_6282 : SW_9000);
    }

    // -----------------------------------------------------------------------
    // INTERNAL AUTHENTICATE
    // -----------------------------------------------------------------------

    private byte[] handleInternalAuthenticate(byte[] apdu)
    {
        if (mState != STATE_READY_FOR_AUTH)
        {
            Log.w(TAG, "INTERNAL AUTHENTICATE in wrong state=" + mState
                    + " (requires STATE_READY_FOR_AUTH)");
            return SW_6985;
        }
        if (mCredPriv32 == null)
        {
            Log.e(TAG, "INTERNAL AUTHENTICATE: private key not loaded");
            return SW_6F00;
        }

        // Extract challenge from APDU data field
        if (apdu.length < 6)
        {
            Log.w(TAG, "INTERNAL AUTHENTICATE: APDU too short, len=" + apdu.length);
            return SW_6A80;
        }
        int lc = apdu[4] & 0xFF;
        if (apdu.length < 5 + lc)
            return SW_6A80;

        // Spec requires exactly 32-byte (256-bit) challenge
        if (lc != 32)
        {
            Log.w(TAG, "INTERNAL AUTHENTICATE: challenge must be 32 bytes, got " + lc);
            return SW_6A80;
        }

        byte[] challenge = Arrays.copyOfRange(apdu, 5, 5 + lc);
        Log.d(TAG, "INTERNAL AUTHENTICATE challenge(" + challenge.length + "): "
                + bytesToHex(challenge));

        // Sign challenge with credential private key
        byte[] sigDER = LeafVerifiedManager.signChallenge(challenge, mCredPriv32);
        if (sigDER == null)
        {
            Log.e(TAG, "INTERNAL AUTHENTICATE: signing failed");
            return SW_6F00;
        }

        Log.d(TAG, "INTERNAL AUTHENTICATE signature(" + sigDER.length + "): "
                + bytesToHex(sigDER));

        // Broadcast success to SendCredentialFragment UI
        Intent intent = new Intent(ACTION_LEAF_CREDENTIAL_SENT);
        intent.setPackage(getPackageName());
        sendBroadcast(intent);

        // Reset state after authentication
        mState = STATE_IDLE;
        return appendSW(sigDER, SW_9000);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Load the credential certificate and private key from SharedPreferences.
     * Called once per SELECT AID. Caches the result so subsequent APDUs are fast.
     *
     * @return true if provisioning data is available
     */
    private boolean loadCredentialData()
    {
        if (mCertDER != null && mCredPriv32 != null) return true;

        Context ctx = getApplicationContext();
        mCertDER    = LeafVerifiedManager.getCredentialCertDER(ctx);
        mCredPriv32 = LeafVerifiedManager.getCredentialPrivateKey(ctx);

        if (mCertDER == null)
        {
            Log.e(TAG, "loadCredentialData: cert not found in SharedPreferences");
            return false;
        }
        if (mCredPriv32 == null)
        {
            Log.e(TAG, "loadCredentialData: private key not found in SharedPreferences");
            return false;
        }
        Log.d(TAG, "loadCredentialData: cert=" + mCertDER.length + "B key=32B");
        return true;
    }

    /** Reset internal state and clear cached data on deactivation. */
    private void resetState()
    {
        mState     = STATE_IDLE;
        mCertDER   = null;
        mCredPriv32 = null;
    }

    /**
     * Build a minimal FCI (File Control Information) response for SELECT AID.
     * Format: 6F <totalLen> 84 <aidLen> <AID> A5 00
     */
    private static byte[] buildFCI(byte[] aid)
    {
        // A5 00 = empty proprietary template
        byte[] a5 = { (byte)0xA5, 0x00 };
        int innerLen = 2 + aid.length + a5.length; // 84 + aidLen + AID + A5 block
        byte[] fci = new byte[2 + innerLen];
        fci[0] = 0x6F;
        fci[1] = (byte)(innerLen & 0xFF);
        fci[2] = (byte)0x84;
        fci[3] = (byte)(aid.length & 0xFF);
        System.arraycopy(aid, 0, fci, 4, aid.length);
        System.arraycopy(a5, 0, fci, 4 + aid.length, a5.length);
        return fci;
    }

    /**
     * Concatenate a data buffer with a 2-byte status word.
     */
    private static byte[] appendSW(byte[] data, byte[] sw)
    {
        if (data == null || data.length == 0)
        {
            return sw;
        }
        byte[] out = new byte[data.length + sw.length];
        System.arraycopy(data, 0, out, 0, data.length);
        System.arraycopy(sw, 0, out, data.length, sw.length);
        return out;
    }

    /** Simple hex string utility. */
    private static String bytesToHex(byte[] b)
    {
        if (b == null) return "(null)";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02X", x & 0xFF));
        return sb.toString();
    }
}
