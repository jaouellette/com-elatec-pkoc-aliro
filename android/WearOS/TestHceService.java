package com.psia.pkoc.wearspike;

import android.content.Intent;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

/**
 * Wear OS HCE Spike — minimal Host APDU service.
 *
 * Purpose: answer the single question of whether Wear OS routes NFC APDUs to
 * a third-party HCE service registered with a custom AID. This service does
 * NOTHING credential-related — it just logs every APDU received and returns
 * the appropriate status word.
 *
 * Test procedure:
 *   1. Build and install this APK on the Pixel Watch
 *   2. From an NFC reader (the ELATEC reader simulator, or any phone running
 *      a tool like NFCTagInfo / TagWriter), send a SELECT-by-AID APDU for
 *      AID = F0 01 02 03 04 05 06
 *   3. Watch logcat on the watch:  adb -s <watch> logcat -s WearHCESpike
 *
 * Expected outcomes:
 *   • Log shows "processCommandApdu: <hex>" → Wear OS HCE routing works.
 *     Full credential-app port is feasible.
 *   • No log entry, or "service not bound" / "no matching AID" from the
 *     framework → Wear OS does not route APDUs to third-party HCE on this
 *     device/OS version. Investigate further or accept the limitation.
 *
 * The first 5 bytes of any received APDU should match: 00 A4 04 00 07
 * (SELECT, by AID, no FCI, Lc=7) followed by the AID itself. The service
 * responds with 9000 to acknowledge.
 */
public class TestHceService extends HostApduService
{
    private static final String TAG = "WearHCESpike";

    /** ISO 7816 success status word. */
    private static final byte[] SW_9000 = { (byte)0x90, 0x00 };

    /** ISO 7816 "INS not supported". */
    private static final byte[] SW_6D00 = { (byte)0x6D, 0x00 };

    /** ISO 7816 "file or application not found". */
    private static final byte[] SW_6A82 = { (byte)0x6A, (byte)0x82 };

    /** Test AID — must match res/xml/apduservice.xml and the reader-side SELECT. */
    private static final byte[] TEST_AID = {
            (byte)0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
    };

    /** Broadcast action to flag spike success to the companion UI activity. */
    public static final String ACTION_APDU_RECEIVED =
            "com.psia.pkoc.wearspike.APDU_RECEIVED";

    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras)
    {
        // The single most important log line in the entire spike.
        // If you see this, Wear OS is routing APDUs to your service. Full stop.
        Log.i(TAG, "processCommandApdu: len=" + (apdu == null ? 0 : apdu.length)
                + " hex=" + bytesToHex(apdu));

        // Broadcast so the watch UI can update visually (helps when adb isn't
        // attached). The MainActivity registers a receiver for this action.
        Intent intent = new Intent(ACTION_APDU_RECEIVED);
        intent.setPackage(getPackageName());
        intent.putExtra("apdu_hex", bytesToHex(apdu));
        sendBroadcast(intent);

        // Minimal protocol: respond 9000 to SELECT-by-AID for our test AID,
        // 6D00 to anything else. This isn't trying to be a real card — just
        // a deterministic acknowledgement that proves routing.
        if (apdu == null || apdu.length < 4)
        {
            return SW_6D00;
        }

        // CLA=00 INS=A4 P1=04 P2=00 means "SELECT by AID"
        if (apdu[0] == 0x00
                && apdu[1] == (byte)0xA4
                && apdu[2] == 0x04
                && apdu[3] == 0x00)
        {
            // Verify the AID matches what we registered
            if (apdu.length >= 5)
            {
                int lc = apdu[4] & 0xFF;
                if (apdu.length >= 5 + lc && lc == TEST_AID.length)
                {
                    boolean match = true;
                    for (int i = 0; i < lc; i++)
                    {
                        if (apdu[5 + i] != TEST_AID[i])
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match)
                    {
                        Log.i(TAG, "SELECT AID matched — returning 9000");
                        return SW_9000;
                    }
                    else
                    {
                        Log.w(TAG, "SELECT AID mismatch");
                        return SW_6A82;
                    }
                }
            }
            return SW_6A82;
        }

        Log.d(TAG, "Non-SELECT APDU received — returning 6D00");
        return SW_6D00;
    }

    @Override
    public void onDeactivated(int reason)
    {
        Log.i(TAG, "onDeactivated reason=" + reason
                + " (0=link_loss, 1=deselected)");
    }

    private static String bytesToHex(byte[] b)
    {
        if (b == null) return "(null)";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02X", x & 0xFF));
        return sb.toString();
    }
}
