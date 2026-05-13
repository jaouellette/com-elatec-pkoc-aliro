package com.psia.pkoc;

import android.app.Activity;
import android.app.KeyguardManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.text.format.DateFormat;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.psia.pkoc.core.AliroDiagnosticLog;
import com.psia.pkoc.core.AliroProvisioningManager;
import com.psia.pkoc.core.CaKeyStore;
import com.psia.pkoc.core.PendingCertEnrollment;

import org.bouncycastle.util.encoders.Hex;

import java.util.Calendar;
import java.util.Date;

/**
 * On-phone confirmation prompt for Flow #2 (cert-based) reader enrollment.
 *
 * Launched from {@link Aliro_HostApduService#handleCertEnrollSubmit} after
 * a reader has presented its pub key + reader_identifier on the enrollment
 * AID via INS 0xE2. Shows the reader's public key, reader_identifier (split
 * into group_id and sub_group_id), and tells the user whether a new CA
 * keypair will be generated for this group_id or an existing one will be
 * reused.
 *
 * On Approve:
 *   1. Look up or generate the CA keypair for the reader's group_id via
 *      {@link CaKeyStore#getOrCreateCAKey}. This also persists the keypair.
 *   2. Sign a profile0000 reader certificate (Aliro §13.3) for the reader's
 *      pub key, using the CA private key, via
 *      {@link AliroProvisioningManager#signProfile0000ForExternalPubKey}.
 *   3. Assemble the wire-format response: TLV 0x90 &lt;cert&gt; 0x85 0x41 &lt;CA pub&gt;.
 *   4. Stage the result in {@link PendingCertEnrollment} so the next 0xE3
 *      poll from the reader returns the cert. The credential side is now
 *      also implicitly provisioned for this reader: the AUTH0/AUTH1 lookup
 *      paths consult {@code CaKeyStore} by group_id, so no separate
 *      "self-provision" step is required.
 *
 * On Reject: call {@link PendingCertEnrollment#recordDeny} and finish.
 * The next 0xE3 poll returns 6A82 once the tick processes the DENIED phase.
 *
 * Differences from {@link EnrollmentConfirmActivity}:
 *   - Reads the staged request from {@link PendingCertEnrollment} rather
 *     than Intent extras. The HCE service has already validated and staged
 *     the request; passing the bytes through an intent again would create
 *     a divergence risk if the activity is re-launched.
 *   - Does the cert signing and assembly work on the click handler. This
 *     is fast (P-256 ECDSA + DER assembly &lt; 50 ms on a current phone) and
 *     keeps the work on the main thread for simplicity.
 *
 * Launch path: same two-phase pattern as
 * {@link EnrollmentConfirmActivity#launch}: try direct startActivity()
 * first, fall back to a full-screen-intent notification when blocked by
 * Android's background-launch restrictions.
 */
public class CertEnrollConfirmActivity extends Activity
{
    private static final String TAG = "AliroCertEnrollConfirm";

    private static final String CHANNEL_ID     = "aliro_cert_enrollment_request";
    private static final String CHANNEL_NAME   = "Aliro Cert-Based Reader Enrollment";
    private static final int    NOTIFICATION_ID = 0xA11A2;

    // SharedPreferences for the configurable cert validity (Settings → Enrollment).
    // The keys here must match the ones used by SettingsFragment in Piece 7.
    private static final String PREFS_APP_NAME              = "AliroAppPrefs";
    private static final String PREF_CERT_VALIDITY_DAYS     = "enroll_cert_validity_days";
    private static final int    DEFAULT_CERT_VALIDITY_DAYS  = 0;  // 0 = §13.3 defaults

    /**
     * Static entry point — call from the HCE service when an 0xE2 submit
     * has been staged in {@link PendingCertEnrollment}. The activity reads
     * the staged data on onCreate; no payload is passed via Intent.
     *
     * Safe to call from any thread.
     */
    public static void launch(Context appCtx)
    {
        if (appCtx == null) return;

        Intent intent = new Intent(appCtx, CertEnrollConfirmActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                      | Intent.FLAG_ACTIVITY_CLEAR_TOP
                      | Intent.FLAG_ACTIVITY_SINGLE_TOP);

        boolean directLaunchOk = false;
        try
        {
            appCtx.startActivity(intent);
            directLaunchOk = true;
            AliroDiagnosticLog.d(TAG, "CertEnrollConfirmActivity launched directly");
        }
        catch (Throwable t)
        {
            AliroDiagnosticLog.w(TAG, "Direct activity launch failed, falling back to notification: "
                    + t.getMessage());
        }

        postFallbackNotification(appCtx, intent, directLaunchOk);
    }

    /** Build and post the fallback heads-up notification. Same pattern as EnrollmentConfirmActivity. */
    private static void postFallbackNotification(Context appCtx,
                                                 Intent fullScreenIntent,
                                                 boolean directLaunchSucceeded)
    {
        int piFlags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
        {
            piFlags |= PendingIntent.FLAG_IMMUTABLE;
        }
        PendingIntent contentPi    = PendingIntent.getActivity(appCtx, 21, fullScreenIntent, piFlags);
        PendingIntent fullScreenPi = PendingIntent.getActivity(appCtx, 22, fullScreenIntent, piFlags);

        NotificationManager nm = (NotificationManager)
                appCtx.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
        {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_HIGH);
            ch.setDescription("A reader is requesting to enroll via cert-based enrollment");
            ch.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
            ch.setShowBadge(false);
            ch.setSound(null, null);
            nm.createNotificationChannel(ch);
        }

        Notification.Builder b = new Notification.Builder(appCtx, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("Reader Enrollment Request (Cert-Based)")
                .setContentText("Tap to approve or reject")
                .setAutoCancel(true)
                .setContentIntent(contentPi)
                .setCategory(Notification.CATEGORY_CALL)
                .setPriority(Notification.PRIORITY_MAX)
                .setVisibility(Notification.VISIBILITY_PUBLIC);

        if (!directLaunchSucceeded)
        {
            b.setFullScreenIntent(fullScreenPi, true);
        }
        try
        {
            nm.notify(NOTIFICATION_ID, b.build());
            AliroDiagnosticLog.d(TAG, "Cert-enroll fallback notification posted "
                    + "(directLaunchSucceeded=" + directLaunchSucceeded + ")");
        }
        catch (Throwable t)
        {
            AliroDiagnosticLog.w(TAG, "Cert-enroll notification post failed: " + t.getMessage());
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);

        // Show over the lock screen and turn on the screen, same pattern as
        // EnrollmentConfirmActivity / TransactionResultActivity.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1)
        {
            setShowWhenLocked(true);
            setTurnScreenOn(true);
            KeyguardManager km = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
            if (km != null) km.requestDismissKeyguard(this, null);
        }
        else
        {
            getWindow().addFlags(
                    WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED
                  | WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON
                  | WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        }

        // Pull the staged request from PendingCertEnrollment. If nothing is
        // staged (e.g. user opened the app from notifications after the
        // request expired), back out cleanly.
        final byte[] readerPub = PendingCertEnrollment.readerPub();
        final byte[] readerId  = PendingCertEnrollment.readerId();
        if (readerPub == null || readerId == null
                || PendingCertEnrollment.getPhase() != PendingCertEnrollment.Phase.AWAITING_USER)
        {
            AliroDiagnosticLog.w(TAG, "No AWAITING_USER request staged; finishing without action");
            Toast.makeText(this, "Enrollment request has expired or was already handled",
                    Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        setContentView(buildLayout(readerPub, readerId));

        // Cancel the fallback notification if we got here via that path.
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm != null)
        {
            try { nm.cancel(NOTIFICATION_ID); } catch (Throwable ignored) { }
        }
    }

    private View buildLayout(byte[] readerPub, byte[] readerId)
    {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        root.setBackgroundColor(0xFF1A1A1A);
        root.setPadding(48, 64, 48, 64);
        root.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));

        TextView title = new TextView(this);
        title.setText("Reader Enrollment\n(Cert-Based)");
        title.setTextSize(26f);
        title.setTextColor(Color.WHITE);
        title.setGravity(Gravity.CENTER);
        title.setTypeface(title.getTypeface(), Typeface.BOLD);
        root.addView(title);

        TextView blurb = new TextView(this);
        blurb.setText("A reader is requesting a signed certificate from this phone. "
                + "Verify the values below, then approve to sign the certificate and "
                + "enroll the reader.");
        blurb.setTextSize(14f);
        blurb.setTextColor(0xCCFFFFFF);
        blurb.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams blurbLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        blurbLp.topMargin    = 16;
        blurbLp.bottomMargin = 24;
        blurb.setLayoutParams(blurbLp);
        root.addView(blurb);

        // Reader pub key
        addLabel(root, "READER PUBLIC KEY");
        addMonoValue(root, formatHexInChunks(Hex.toHexString(readerPub), 8));

        // Split readerId into group + sub-group for clarity, per wire spec §4.2.
        String readerIdHex = Hex.toHexString(readerId);
        String groupHex    = readerIdHex.substring(0, 32);   // first 16 bytes
        String subGroupHex = readerIdHex.substring(32, 64);  // second 16 bytes

        addLabel(root, "GROUP ID");
        addMonoValue(root, formatHexInChunks(groupHex, 8));

        addLabel(root, "SUB-GROUP ID");
        addMonoValue(root, formatHexInChunks(subGroupHex, 8));

        // CA key status line — does this group_id already have a CA keypair?
        byte[] groupIdBytes = new byte[16];
        System.arraycopy(readerId, 0, groupIdBytes, 0, 16);
        CaKeyStore.CaKeyEntry existing = CaKeyStore.getCAKey(this, groupIdBytes);

        addLabel(root, "CA KEY STATUS");
        TextView statusText = new TextView(this);
        statusText.setTextSize(13f);
        statusText.setTextColor(Color.WHITE);
        statusText.setGravity(Gravity.CENTER);
        if (existing != null)
        {
            CharSequence dateStr = DateFormat.format("yyyy-MM-dd", new Date(existing.createdAtMs));
            statusText.setText("Will sign with EXISTING CA keypair\n(created " + dateStr + ")");
        }
        else
        {
            statusText.setText("Will generate a NEW CA keypair\nfor this Group ID");
        }
        LinearLayout.LayoutParams statusLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        statusLp.topMargin = 4;
        statusText.setLayoutParams(statusLp);
        root.addView(statusText);

        // Buttons
        LinearLayout btnRow = new LinearLayout(this);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);
        btnRow.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        rowLp.topMargin = 40;
        btnRow.setLayoutParams(rowLp);

        Button reject = new Button(this);
        reject.setText("REJECT");
        reject.setOnClickListener(v -> {
            AliroDiagnosticLog.i(TAG, "User rejected cert-based enrollment");
            PendingCertEnrollment.recordDeny();
            finishAndRemoveTask();
        });
        LinearLayout.LayoutParams rejectLp = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        rejectLp.rightMargin = 16;
        reject.setLayoutParams(rejectLp);
        btnRow.addView(reject);

        Button approve = new Button(this);
        approve.setText("APPROVE");
        approve.setOnClickListener(v -> {
            onApprove(readerPub, readerId);
        });
        LinearLayout.LayoutParams approveLp = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        approveLp.leftMargin = 16;
        approve.setLayoutParams(approveLp);
        btnRow.addView(approve);

        root.addView(btnRow);
        return root;
    }

    /**
     * Approve click handler — does the actual signing and stages the
     * response for the next 0xE3 fetch.
     */
    private void onApprove(byte[] readerPub, byte[] readerId)
    {
        try
        {
            // 1. Look up or generate the CA keypair for this group_id, and
            // persist the reader's own pub key on the entry so AUTH1
            // signature verification can find it later per §8.3.3.4.5
            // no-cert branch (where the User Device must "look up the
            // reader public key using the reader_group_identifier").
            byte[] groupIdBytes = new byte[16];
            System.arraycopy(readerId, 0, groupIdBytes, 0, 16);
            CaKeyStore.CaKeyEntry ca = CaKeyStore.getOrCreateCAKey(
                    getApplicationContext(), groupIdBytes, readerPub);

            // 2. Compute validity per Settings (0 days = §13.3 defaults).
            Date notBefore = null;
            Date notAfter  = null;
            int  validityDays = getConfiguredCertValidityDays();
            if (validityDays > 0)
            {
                Calendar cal = Calendar.getInstance();
                notBefore = cal.getTime();
                cal.add(Calendar.DAY_OF_YEAR, validityDays);
                notAfter = cal.getTime();
            }

            // 3. Sign the cert.
            byte[] cert = AliroProvisioningManager.signProfile0000ForExternalPubKey(
                    readerPub,
                    ca.caPriv,
                    ca.caPub,
                    notBefore,
                    notAfter);

            // 4. Assemble the wire-format response: TLV 0x90 <cert> 0x85 0x41 <CA pub>.
            byte[] payload = buildResponsePayload(cert, ca.caPub);

            // 5. Stage the result for the next 0xE3 poll.
            PendingCertEnrollment.recordApprove(payload);

            AliroDiagnosticLog.i(TAG, "Cert-based enrollment approved: cert="
                    + cert.length + "B, payload=" + payload.length + "B, "
                    + (validityDays > 0
                            ? "validity=" + validityDays + " days"
                            : "validity=§13.3 defaults"));
            Toast.makeText(this, "Reader enrolled — return phone to reader to complete",
                    Toast.LENGTH_LONG).show();
        }
        catch (Exception e)
        {
            AliroDiagnosticLog.e(TAG, "Cert-based enrollment failed during signing", e);
            // Record as deny so the reader doesn't wait forever — it will see 6A82
            // on the next 0xE3 fetch.
            PendingCertEnrollment.recordDeny();
            Toast.makeText(this, "Enrollment failed — see diagnostic log",
                    Toast.LENGTH_LONG).show();
        }
        finishAndRemoveTask();
    }

    /**
     * Build the 0xE3 fetch response payload: TLV 0x90 &lt;cert&gt; 0x85 0x41 &lt;CA pub&gt;.
     * Cert length uses BER short form when &lt; 128, otherwise 0x81 &lt;Ll&gt;.
     * The CA pub key is always 65 bytes (uncompressed P-256) so its length
     * byte is the literal 0x41.
     */
    private static byte[] buildResponsePayload(byte[] cert, byte[] caPub)
    {
        if (caPub == null || caPub.length != 65)
        {
            throw new IllegalArgumentException("CA pub must be 65 bytes uncompressed");
        }
        // Cert TLV header size: 2 bytes if cert.length < 128, else 3 bytes.
        int certTlvHeaderLen = (cert.length < 128) ? 2 : 3;
        int totalLen = certTlvHeaderLen + cert.length + 2 + 65;
        byte[] out = new byte[totalLen];
        int o = 0;
        out[o++] = (byte) 0x90;
        if (cert.length < 128)
        {
            out[o++] = (byte) cert.length;
        }
        else
        {
            out[o++] = (byte) 0x81;
            out[o++] = (byte) cert.length;
        }
        System.arraycopy(cert, 0, out, o, cert.length);
        o += cert.length;
        out[o++] = (byte) 0x85;
        out[o++] = (byte) 0x41;
        System.arraycopy(caPub, 0, out, o, 65);
        return out;
    }

    private int getConfiguredCertValidityDays()
    {
        SharedPreferences prefs = getSharedPreferences(PREFS_APP_NAME, Context.MODE_PRIVATE);
        int days = prefs.getInt(PREF_CERT_VALIDITY_DAYS, DEFAULT_CERT_VALIDITY_DAYS);
        if (days < 0) days = DEFAULT_CERT_VALIDITY_DAYS;
        return days;
    }

    // ---- small layout helpers --------------------------------------------

    private void addLabel(LinearLayout parent, String text)
    {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextSize(11f);
        tv.setTextColor(0x99FFFFFF);
        tv.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = 16;
        tv.setLayoutParams(lp);
        parent.addView(tv);
    }

    private void addMonoValue(LinearLayout parent, String text)
    {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextSize(13f);
        tv.setTextColor(Color.WHITE);
        tv.setGravity(Gravity.CENTER);
        tv.setTypeface(Typeface.MONOSPACE);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = 4;
        tv.setLayoutParams(lp);
        parent.addView(tv);
    }

    /** Insert a space every {@code chunkSize} hex chars to make eyeballing easier. */
    private static String formatHexInChunks(String hex, int chunkSize)
    {
        if (hex == null || chunkSize <= 0) return hex;
        StringBuilder sb = new StringBuilder(hex.length() + hex.length() / chunkSize);
        for (int i = 0; i < hex.length(); i += chunkSize)
        {
            if (i > 0) sb.append(' ');
            sb.append(hex, i, Math.min(i + chunkSize, hex.length()));
        }
        return sb.toString();
    }
}
