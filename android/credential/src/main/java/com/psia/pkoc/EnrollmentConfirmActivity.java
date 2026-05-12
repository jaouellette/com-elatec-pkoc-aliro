package com.psia.pkoc;

import android.app.Activity;
import android.app.KeyguardManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
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

import org.bouncycastle.util.encoders.Hex;

/**
 * On-phone confirmation prompt for over-NFC reader enrollment.
 *
 * Launched from {@link Aliro_HostApduService#handleEnrollmentWrite} after
 * a reader has tapped the phone in enrollment mode. Shows the reader's
 * public key and reader ID so the user can visually verify the values
 * before approving. Approving calls
 * {@link AliroProvisioningManager#storeEnrolledReader} to persist the
 * provisioning. Rejecting just dismisses the screen and stores nothing.
 *
 * Launch path: This activity uses a full-screen intent on a heads-up
 * notification, identical to {@link TransactionResultActivity}, so that
 * it pops up over the lock screen if the phone was idle when the tap
 * happened. The notification itself is what triggers the lock-screen
 * override on Android 14+; the bare startActivity() from a background
 * service is no longer reliable.
 */
public class EnrollmentConfirmActivity extends Activity
{
    private static final String TAG = "AliroEnrollConfirm";

    private static final String EXTRA_PUB        = "pub";
    private static final String EXTRA_READER_ID  = "readerId";

    private static final String CHANNEL_ID    = "aliro_enrollment_request";
    private static final String CHANNEL_NAME  = "Aliro Reader Enrollment";
    private static final int    NOTIFICATION_ID = 0xA11A1;

    /**
     * Static entry point — call from the HCE service when an enrollment
     * payload arrives. Tries two launch paths in order:
     *
     *   1. Direct startActivity() — works when the user is currently in
     *      the app (the expected case, since enrollment requires them to
     *      have just turned on Enrollment Mode in Aliro Config).
     *
     *   2. Full-screen-intent notification as a fallback — used when
     *      direct activity launch is blocked by Android's background-launch
     *      restrictions (typical when the screen is off). The notification
     *      auto-launches the activity if USE_FULL_SCREEN_INTENT and
     *      POST_NOTIFICATIONS are granted; otherwise it shows as a heads-up
     *      banner the user can tap.
     *
     * Safe to call from any thread; the actual UI work happens via the
     * activity lifecycle on whatever thread Android decides.
     */
    public static void launch(Context appCtx, byte[] readerPub, byte[] readerId)
    {
        if (appCtx == null || readerPub == null || readerId == null) return;

        Intent intent = new Intent(appCtx, EnrollmentConfirmActivity.class);
        intent.putExtra(EXTRA_PUB,       readerPub);
        intent.putExtra(EXTRA_READER_ID, readerId);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                      | Intent.FLAG_ACTIVITY_CLEAR_TOP
                      | Intent.FLAG_ACTIVITY_SINGLE_TOP);

        // Path 1: direct activity start. This works as long as the app has
        // had a recent foreground interaction (which is true here — the user
        // just toggled Enrollment Mode and tapped a reader).
        boolean directLaunchOk = false;
        try
        {
            appCtx.startActivity(intent);
            directLaunchOk = true;
            AliroDiagnosticLog.d(TAG, "EnrollmentConfirmActivity launched directly");
        }
        catch (Throwable t)
        {
            // Background-launch restriction or some other policy issue.
            // Fall through to the notification path below.
            AliroDiagnosticLog.w(TAG, "Direct activity launch failed, falling back to notification: "
                    + t.getMessage());
        }

        // Path 2: notification with full-screen intent. Posted as a
        // fallback when direct launch failed, OR unconditionally so the
        // user has something tappable in their notification shade if the
        // activity gets dismissed before they see it.
        postFallbackNotification(appCtx, intent, directLaunchOk);
    }

    /**
     * Build and post the fallback heads-up notification. Always posted —
     * even when direct launch succeeded — so the user has something to tap
     * if the activity is dismissed before they react, or if the OS routes
     * the full-screen intent rather than auto-launching the activity.
     */
    private static void postFallbackNotification(Context appCtx,
                                                 Intent fullScreenIntent,
                                                 boolean directLaunchSucceeded)
    {
        int piFlags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
        {
            piFlags |= PendingIntent.FLAG_IMMUTABLE;
        }
        PendingIntent contentPi    = PendingIntent.getActivity(appCtx, 11, fullScreenIntent, piFlags);
        PendingIntent fullScreenPi = PendingIntent.getActivity(appCtx, 12, fullScreenIntent, piFlags);

        NotificationManager nm = (NotificationManager)
                appCtx.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
        {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_HIGH);
            ch.setDescription("A reader is requesting to enroll with this credential");
            ch.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
            ch.setShowBadge(false);
            ch.setSound(null, null);
            nm.createNotificationChannel(ch);
        }

        Notification.Builder b = new Notification.Builder(appCtx, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("Reader Enrollment Request")
                .setContentText("Tap to approve or reject")
                .setAutoCancel(true)
                .setContentIntent(contentPi)
                .setCategory(Notification.CATEGORY_CALL)
                .setPriority(Notification.PRIORITY_MAX)
                .setVisibility(Notification.VISIBILITY_PUBLIC);

        // Only attach the full-screen intent when direct launch failed —
        // otherwise we'd risk launching the activity twice.
        if (!directLaunchSucceeded)
        {
            b.setFullScreenIntent(fullScreenPi, true);
        }
        try
        {
            nm.notify(NOTIFICATION_ID, b.build());
            AliroDiagnosticLog.d(TAG, "Enrollment fallback notification posted "
                    + "(directLaunchSucceeded=" + directLaunchSucceeded + ")");
        }
        catch (Throwable t)
        {
            // POST_NOTIFICATIONS not granted on Android 13+ will land here.
            // Not fatal — direct launch may already have succeeded.
            AliroDiagnosticLog.w(TAG, "Enrollment notification post failed: " + t.getMessage());
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);

        // Show over the lock screen and turn on the screen, same pattern
        // as TransactionResultActivity.
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

        final byte[] readerPub = getIntent().getByteArrayExtra(EXTRA_PUB);
        final byte[] readerId  = getIntent().getByteArrayExtra(EXTRA_READER_ID);
        if (readerPub == null || readerId == null
                || readerPub.length != 65 || readerId.length != 32)
        {
            AliroDiagnosticLog.e(TAG, "Enrollment activity launched with invalid extras");
            finish();
            return;
        }

        setContentView(buildLayout(readerPub, readerId));

        // If we got here via the fallback notification, dismiss it so it
        // doesn't linger in the user's shade. Harmless no-op if the
        // notification was never posted (e.g., POST_NOTIFICATIONS denied).
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
        title.setText("Reader Enrollment");
        title.setTextSize(28f);
        title.setTextColor(Color.WHITE);
        title.setGravity(Gravity.CENTER);
        title.setTypeface(title.getTypeface(), Typeface.BOLD);
        root.addView(title);

        TextView blurb = new TextView(this);
        blurb.setText("A reader is requesting to enroll with this credential. "
                + "Verify the values below match the reader you intend to provision, "
                + "then approve or reject.");
        blurb.setTextSize(14f);
        blurb.setTextColor(0xCCFFFFFF);
        blurb.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams blurbLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        blurbLp.topMargin = 16;
        blurbLp.bottomMargin = 32;
        blurb.setLayoutParams(blurbLp);
        root.addView(blurb);

        // Reader pub key
        addLabel(root, "READER PUBLIC KEY");
        addMonoValue(root, formatHexInChunks(Hex.toHexString(readerPub), 8));

        // Reader ID
        addLabel(root, "READER ID");
        addMonoValue(root, formatHexInChunks(Hex.toHexString(readerId), 8));

        // Group ID (computed) — helpful so the user can cross-check against
        // a value the reader may display physically.
        addLabel(root, "GROUP ID (computed)");
        addMonoValue(root, formatHexInChunks(Hex.toHexString(readerId).substring(0, 32), 8));

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
            AliroDiagnosticLog.i(TAG, "User rejected enrollment");
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
            String summary = AliroProvisioningManager.storeEnrolledReader(
                    getApplicationContext(), readerPub, readerId);
            if (summary != null)
            {
                AliroDiagnosticLog.i(TAG, "User approved enrollment; stored");
                Toast.makeText(this, "Reader enrolled", Toast.LENGTH_SHORT).show();
            }
            else
            {
                AliroDiagnosticLog.w(TAG, "User approved but storage failed");
                Toast.makeText(this, "Enrollment failed — see diagnostic log",
                        Toast.LENGTH_LONG).show();
            }
            finishAndRemoveTask();
        });
        LinearLayout.LayoutParams approveLp = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        approveLp.leftMargin = 16;
        approve.setLayoutParams(approveLp);
        btnRow.addView(approve);

        root.addView(btnRow);
        return root;
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
