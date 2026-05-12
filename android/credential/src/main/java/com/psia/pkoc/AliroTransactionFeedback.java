package com.psia.pkoc;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.media.AudioManager;
import android.media.ToneGenerator;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;

import com.psia.pkoc.core.AliroDiagnosticLog;

/**
 * Post-transaction user feedback for Aliro credential exchanges.
 *
 * Two channels of feedback are provided when an Aliro transaction completes:
 *
 *   1. Audible tone pair:
 *        Access granted → low beep followed by high beep
 *        Access denied  → high beep followed by low beep
 *
 *      The tones play through ToneGenerator on the NOTIFICATION audio stream
 *      so they respect Do Not Disturb and the user's notification volume.
 *      Tones are spaced and short enough to be perceived as a single chirp
 *      pattern, similar to a contactless payment terminal.
 *
 *   2. Heads-up notification with a full-screen intent:
 *        The notification lights up the screen and surfaces the result
 *        (granted / denied) as a top-of-screen banner. Tapping it opens
 *        {@link TransactionResultActivity}, which is also auto-launched as
 *        a full-screen activity on devices where the screen was off and the
 *        full-screen-intent permission is granted (USE_FULL_SCREEN_INTENT).
 *
 * Public entry point: {@link #notifyTransactionComplete(Context, boolean, int)}.
 *
 * Callable from any thread. ToneGenerator playback is posted to a worker
 * thread to avoid blocking the caller (which on the HCE path is the main
 * thread serving APDUs and we don't want to add even a few ms of latency).
 */
public final class AliroTransactionFeedback
{
    private static final String TAG = "AliroTxFeedback";

    /** Notification channel for transaction result heads-up. */
    private static final String CHANNEL_ID   = "aliro_transaction_result";
    private static final String CHANNEL_NAME = "Aliro Credential Result";
    private static final int    NOTIFICATION_ID = 0xA11A0; // arbitrary but stable

    /** Tone parameters. */
    private static final int TONE_VOLUME      = 80;  // 0-100
    private static final int TONE_DURATION_MS = 110; // each beep length
    private static final int TONE_GAP_MS      = 60;  // silence between the two beeps

    /**
     * Two distinct DTMF-style tones that the Android ToneGenerator
     * supports natively (no audio assets required).
     *
     * TONE_PROP_BEEP is "high" (~1200 Hz). TONE_PROP_BEEP2 is "low"
     * (~400 Hz). Picked because the contrast is audible on a phone
     * speaker even with background noise.
     */
    private static final int TONE_HIGH = ToneGenerator.TONE_PROP_BEEP;
    private static final int TONE_LOW  = ToneGenerator.TONE_PROP_BEEP2;

    private AliroTransactionFeedback() { /* static-only */ }

    /**
     * Fire the post-transaction feedback. Safe to call from the HCE service
     * thread — all heavy work (tone playback, activity launch, notification
     * building) is posted off-thread.
     *
     * @param ctx           any Context (application context will be used)
     * @param accessGranted true if the reader signaled success (0x97 first byte = 0x01)
     * @param readerState   the second byte of the 0x97 status TLV, for display
     *                      in the notification (e.g. 0x82 "unknown", 0x26 "hardware issue")
     */
    public static void notifyTransactionComplete(Context ctx, boolean accessGranted, int readerState)
    {
        if (ctx == null) return;
        final Context appCtx = ctx.getApplicationContext();

        // Posting tone playback to a worker thread keeps the HCE main thread
        // free. Even if ToneGenerator allocation only takes a few ms, that's
        // a few ms we don't want to spend on the APDU return path.
        new Thread(() ->
        {
            try
            {
                playTonePair(accessGranted);
            }
            catch (Throwable t)
            {
                AliroDiagnosticLog.w(TAG, "tone playback failed", t);
            }
        }, "AliroTxFeedback-Tone").start();

        // Visual feedback: launch the result activity directly, then post a
        // notification as fallback. This mirrors EnrollmentConfirmActivity —
        // direct startActivity works when the app has had recent foreground
        // interaction (typical for an active tap-to-reader workflow), and
        // the notification path covers the screen-off case via full-screen
        // intent. Main-thread Handler because some OEM NotificationManager
        // implementations are touchy about being called from background
        // threads.
        new Handler(Looper.getMainLooper()).post(() ->
        {
            try
            {
                launchOrNotify(appCtx, accessGranted, readerState);
            }
            catch (Throwable t)
            {
                AliroDiagnosticLog.w(TAG, "visual feedback failed", t);
            }
        });
    }

    // -------------------------------------------------------------------------
    // Tone playback
    // -------------------------------------------------------------------------

    private static void playTonePair(boolean accessGranted)
    {
        ToneGenerator tg = null;
        try
        {
            tg = new ToneGenerator(AudioManager.STREAM_NOTIFICATION, TONE_VOLUME);

            // Granted: low → high (ascending, "success" cadence)
            // Denied:  high → low (descending, "denial" cadence)
            int first  = accessGranted ? TONE_LOW  : TONE_HIGH;
            int second = accessGranted ? TONE_HIGH : TONE_LOW;

            tg.startTone(first, TONE_DURATION_MS);
            Thread.sleep(TONE_DURATION_MS + TONE_GAP_MS);
            tg.startTone(second, TONE_DURATION_MS);
            // Let the second tone finish playing before releasing the
            // ToneGenerator — otherwise the tail of the tone is cut off on
            // some devices.
            Thread.sleep(TONE_DURATION_MS + 40);
        }
        catch (InterruptedException ie)
        {
            Thread.currentThread().interrupt();
        }
        finally
        {
            if (tg != null)
            {
                try { tg.release(); } catch (Exception ignored) { }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Visual feedback: try direct activity launch, fall back to notification
    // -------------------------------------------------------------------------

    private static void launchOrNotify(Context appCtx, boolean accessGranted, int readerState)
    {
        Intent resultIntent = new Intent(appCtx, TransactionResultActivity.class);
        resultIntent.putExtra(TransactionResultActivity.EXTRA_GRANTED, accessGranted);
        resultIntent.putExtra(TransactionResultActivity.EXTRA_READER_STATE, readerState);
        resultIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                            | Intent.FLAG_ACTIVITY_CLEAR_TOP
                            | Intent.FLAG_ACTIVITY_SINGLE_TOP);

        // Path 1: direct activity start. Works when the app has had recent
        // foreground interaction, which is the typical state during an
        // active tap-to-reader test.
        boolean directLaunchOk = false;
        try
        {
            appCtx.startActivity(resultIntent);
            directLaunchOk = true;
            AliroDiagnosticLog.d(TAG, "TransactionResultActivity launched directly");
        }
        catch (Throwable t)
        {
            AliroDiagnosticLog.w(TAG, "Direct activity launch failed, falling back to notification: "
                    + t.getMessage());
        }

        // Path 2: notification. Always posted so the user has something in
        // the shade if they dismiss the activity, and as a screen-off
        // fallback. Skip the full-screen intent if direct launch succeeded
        // (avoids launching the activity twice).
        postNotification(appCtx, resultIntent, accessGranted, readerState, directLaunchOk);
    }

    private static void postNotification(Context appCtx,
                                         Intent resultIntent,
                                         boolean accessGranted,
                                         int readerState,
                                         boolean directLaunchSucceeded)
    {
        NotificationManager nm = (NotificationManager)
                appCtx.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;

        ensureChannel(nm);

        int piFlags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
        {
            piFlags |= PendingIntent.FLAG_IMMUTABLE;
        }
        PendingIntent contentPi    = PendingIntent.getActivity(appCtx, 1, resultIntent, piFlags);
        PendingIntent fullScreenPi = PendingIntent.getActivity(appCtx, 2, resultIntent, piFlags);

        String title = accessGranted ? "Access Granted" : "Access Denied";
        String body  = "Aliro credential exchange complete"
                + (readerState >= 0 ? String.format(" (reader state 0x%02X)", readerState) : "");

        Notification.Builder b = new Notification.Builder(appCtx, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
                .setContentTitle(title)
                .setContentText(body)
                .setAutoCancel(true)
                .setOngoing(false)
                .setContentIntent(contentPi)
                .setCategory(Notification.CATEGORY_CALL)
                .setPriority(Notification.PRIORITY_MAX)
                .setVisibility(Notification.VISIBILITY_PUBLIC);

        if (!directLaunchSucceeded)
        {
            // Only attach the full-screen intent when direct launch failed,
            // to avoid launching the activity twice if the user is on the
            // lock screen and the OS auto-launches via the intent.
            b.setFullScreenIntent(fullScreenPi, true);
        }

        try
        {
            nm.notify(NOTIFICATION_ID, b.build());
        }
        catch (Throwable t)
        {
            // POST_NOTIFICATIONS not granted on Android 13+ will land here.
            // Not fatal if direct launch already succeeded.
            AliroDiagnosticLog.w(TAG, "transaction notification post failed: " + t.getMessage());
        }
    }

    /**
     * Create the notification channel on first use. Idempotent — calling
     * createNotificationChannel on an existing channel is a no-op.
     *
     * IMPORTANCE_HIGH makes the notification appear as a heads-up banner
     * even when the user isn't on the lock screen. Required for full-screen
     * intent on Android 8+.
     */
    private static void ensureChannel(NotificationManager nm)
    {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_HIGH);
        ch.setDescription("Result of an Aliro credential reader tap");
        ch.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
        ch.setShowBadge(false);
        // We provide our own ToneGenerator beeps, so suppress the channel's
        // default notification sound. The vibration default is left on for
        // accessibility (silent-mode users still feel the buzz).
        ch.setSound(null, null);
        nm.createNotificationChannel(ch);
    }
}
