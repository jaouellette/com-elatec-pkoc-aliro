package com.psia.pkoc;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

/**
 * Full-screen display for an Aliro credential transaction.
 *
 * Two phases are shown by the same activity instance:
 *
 *   1. IN PROGRESS ("reading") — launched by
 *      {@link AliroTransactionFeedback#notifyTransactionStarted(Context)} the
 *      moment the reader SELECTs the credential. A neutral screen with a
 *      spinner and "Hold your phone on the reader" tells the user the tap was
 *      detected and to keep still. This is the feedback that was previously
 *      missing during the multi-second exchange.
 *
 *   2. RESULT (granted / denied) — the existing completion path
 *      ({@link AliroTransactionFeedback#notifyTransactionComplete}) re-launches
 *      this activity (SINGLE_TOP) with the result extras. Because the activity
 *      is already on top showing "reading", that arrives via {@link #onNewIntent}
 *      and flips the same screen to GRANTED/DENIED in place — no second window.
 *
 * Launched the same two ways as before (notification tap, or full-screen intent
 * over the lock screen). UI is built in code to avoid adding a resource file.
 *
 * One physical tap can produce several SELECTs (e.g. a primary-identity reject
 * followed by a secondary-identity retry). Each fires notifyTransactionStarted,
 * but since the activity is single-top those just re-render the same "reading"
 * state, so there is no flicker or relaunch.
 */
public class TransactionResultActivity extends Activity
{
    /** Boolean extra: true if access was granted (result phase). */
    public static final String EXTRA_GRANTED       = "granted";
    /** Int extra: reader state byte from the 0x97 status TLV (or -1 if absent). */
    public static final String EXTRA_READER_STATE  = "readerState";
    /** Boolean extra: true while the transaction is still running (reading phase). */
    public static final String EXTRA_IN_PROGRESS   = "inProgress";

    /**
     * The RESULT phase does NOT auto-dismiss. It stays until the user closes it
     * (tap, Dismiss button, or system finish), so the reader re-initiating the
     * next transaction can't flash the Admit/Deny result away. While a result
     * is up, {@link AliroTransactionFeedback} suppresses the next reading
     * screen; closing this window re-arms it via
     * {@link AliroTransactionFeedback#onResultDismissed()}.
     */
    /**
     * Safety timeout for the IN-PROGRESS phase. If no result arrives within
     * this window (e.g. the user pulled the phone away before the read
     * completed, so the reader never sent a status), dismiss rather than
     * leaving a spinner on screen forever. Generous enough to cover a slow
     * double step-up plus a re-tap.
     */
    private static final long PROGRESS_TIMEOUT_MS = 12000L;

    private final Handler handler = new Handler(Looper.getMainLooper());

    /** True when the currently shown phase is a result (granted/denied). */
    private boolean showingResult = false;

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);

        // Show over the lock screen and turn the screen on, so both the
        // "reading" and result phases are visible when the phone was idle at
        // tap time.
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

        render(getIntent());
    }

    /**
     * A new intent for the already-showing activity (single-top). This is how
     * the result phase replaces the reading phase, and how repeated SELECTs in
     * one tap re-assert the reading phase without spawning a new window.
     */
    @Override
    protected void onNewIntent(Intent intent)
    {
        super.onNewIntent(intent);
        setIntent(intent);
        render(intent);
    }

    /** (Re)build the screen for whichever phase the intent describes. */
    private void render(Intent intent)
    {
        // Drop any pending dismiss from a previous phase before scheduling the
        // one that matches the phase we're about to show.
        handler.removeCallbacksAndMessages(null);

        boolean inProgress = intent != null && intent.getBooleanExtra(EXTRA_IN_PROGRESS, false);
        if (inProgress)
        {
            showingResult = false;
            renderProgress();
            // Don't linger forever if the read is abandoned mid-flight.
            handler.postDelayed(this::finishAndRemoveTask, PROGRESS_TIMEOUT_MS);
            return;
        }

        showingResult = true;
        boolean granted     = intent != null && intent.getBooleanExtra(EXTRA_GRANTED, false);
        int     readerState = intent != null ? intent.getIntExtra(EXTRA_READER_STATE, -1) : -1;
        renderResult(granted, readerState);
        // No auto-dismiss: the result stays until the user closes it (see
        // onDestroy, which re-arms the reading screen for the next tap).
    }

    // -------------------------------------------------------------------------
    // Reading phase
    // -------------------------------------------------------------------------

    private void renderProgress()
    {
        LinearLayout root = newRoot(0xFF1F3A5F); // deep neutral blue — clearly "working", not a verdict

        ProgressBar spinner = new ProgressBar(this);
        spinner.setIndeterminate(true);
        LinearLayout.LayoutParams spLp = new LinearLayout.LayoutParams(120, 120);
        spLp.bottomMargin = 36;
        spinner.setLayoutParams(spLp);
        root.addView(spinner);

        TextView title = new TextView(this);
        title.setText("READING\u2026");
        title.setTextSize(36f);
        title.setTextColor(Color.WHITE);
        title.setGravity(Gravity.CENTER);
        title.setTypeface(title.getTypeface(), android.graphics.Typeface.BOLD);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("Hold your phone on the reader");
        sub.setTextSize(16f);
        sub.setTextColor(0xCCFFFFFF);
        sub.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        subLp.topMargin = 24;
        sub.setLayoutParams(subLp);
        root.addView(sub);

        // No Dismiss button and no tap-to-dismiss here: dismissing mid-read
        // would defeat the purpose. The safety timeout handles abandonment.
        setContentView(root);
    }

    // -------------------------------------------------------------------------
    // Result phase
    // -------------------------------------------------------------------------

    private void renderResult(boolean granted, int readerState)
    {
        LinearLayout root = newRoot(granted ? 0xFF1B7F38 : 0xFFB31B1B);
        // Tap-anywhere to dismiss, as before.
        root.setOnClickListener(v -> finishAndRemoveTask());

        TextView title = new TextView(this);
        title.setText(granted ? "ACCESS GRANTED" : "ACCESS DENIED");
        title.setTextSize(40f);
        title.setTextColor(Color.WHITE);
        title.setGravity(Gravity.CENTER);
        title.setTypeface(title.getTypeface(), android.graphics.Typeface.BOLD);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText(buildSubtitle(granted, readerState));
        sub.setTextSize(16f);
        sub.setTextColor(0xCCFFFFFF);
        sub.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        subLp.topMargin = 24;
        sub.setLayoutParams(subLp);
        root.addView(sub);

        Button dismiss = new Button(this);
        dismiss.setText("DISMISS");
        dismiss.setOnClickListener(v -> finishAndRemoveTask());
        LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        btnLp.topMargin = 48;
        dismiss.setLayoutParams(btnLp);
        root.addView(dismiss);

        setContentView(root);
    }

    private LinearLayout newRoot(int bgColor)
    {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        root.setBackgroundColor(bgColor);
        root.setPadding(48, 48, 48, 48);
        root.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        return root;
    }

    @Override
    protected void onDestroy()
    {
        handler.removeCallbacksAndMessages(null);
        // If the user is closing a result window (not a config-change recreate,
        // and not the reading phase), re-arm the reading screen for the next tap.
        if (isFinishing() && showingResult)
        {
            AliroTransactionFeedback.onResultDismissed();
        }
        super.onDestroy();
    }

    private static String buildSubtitle(boolean granted, int readerState)
    {
        if (granted)
        {
            if (readerState == 0x00) return "Reader state: secure";
            if (readerState == 0x01) return "Reader state: unsecure";
            if (readerState == 0x02) return "Reader state: obstructed";
            if (readerState == 0x80) return "Reader state: entering secure";
            if (readerState == 0x81) return "Reader state: entering unsecure";
            if (readerState == 0x82) return "Reader state: unknown";
            return readerState >= 0
                    ? String.format("Reader state: 0x%02X", readerState)
                    : "";
        }
        // Denied — second byte is a reason code per spec Table 8-18.
        switch (readerState)
        {
            case 0x01: return "Reason: credential public key not found";
            case 0x02: return "Reason: credential public key expired";
            case 0x03: return "Reason: credential public key not trusted";
            case 0x04: return "Reason: invalid user-device signature";
            case 0x06: return "Reason: invalid data format";
            case 0x07: return "Reason: invalid data content";
            case 0x20: return "Reason: status word error";
            case 0x21: return "Reason: no key slot in response";
            case 0x22: return "Reason: no public key in response";
            case 0x23: return "Reason: no user-device signature";
            case 0x25: return "Reason: invalid access rights";
            case 0x26: return "Reason: reader hardware issue";
            default:
                return readerState >= 0
                        ? String.format("Reason: 0x%02X", readerState)
                        : "Reason: not reported";
        }
    }
}
