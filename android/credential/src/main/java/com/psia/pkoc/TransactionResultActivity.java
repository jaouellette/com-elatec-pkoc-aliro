package com.psia.pkoc;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
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
import android.widget.TextView;

/**
 * Full-screen result display for a completed Aliro credential transaction.
 *
 * Launched two ways:
 *
 *   1. Tap on the heads-up notification — normal activity start.
 *   2. Full-screen intent from {@link AliroTransactionFeedback} — Android
 *      auto-launches this activity over the lock screen if USE_FULL_SCREEN_INTENT
 *      is granted. This is the path that gives the user the "phone in pocket,
 *      tap to reader, screen lights up showing GRANTED/DENIED" experience.
 *
 * The activity dismisses itself after a few seconds, but the user can also
 * tap anywhere or use the Dismiss button to close immediately.
 *
 * UI is built in code rather than XML so we don't introduce another resource
 * file. The visual is intentionally simple: full-screen colored background
 * with a large text label.
 */
public class TransactionResultActivity extends Activity
{
    /** Boolean extra: true if access was granted. */
    public static final String EXTRA_GRANTED       = "granted";
    /** Int extra: reader state byte from the 0x97 status TLV (or -1 if absent). */
    public static final String EXTRA_READER_STATE  = "readerState";

    /** Auto-dismiss timeout — long enough to read, short enough to be unobtrusive. */
    private static final long AUTO_DISMISS_MS = 4000L;

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);

        // Show this activity over the lock screen and turn the screen on.
        // Required for the full-screen intent path to actually be visible
        // when the phone was in the user's pocket at tap time.
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

        boolean granted     = getIntent().getBooleanExtra(EXTRA_GRANTED, false);
        int     readerState = getIntent().getIntExtra(EXTRA_READER_STATE, -1);

        // Build the layout programmatically.
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        // Green for granted, red for denied. Strong/saturated tones to be
        // unambiguous at a glance.
        root.setBackgroundColor(granted ? 0xFF1B7F38 : 0xFFB31B1B);
        root.setPadding(48, 48, 48, 48);
        root.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        // Tap-anywhere to dismiss.
        root.setOnClickListener(v -> finishAndRemoveTask());

        // Main label.
        TextView title = new TextView(this);
        title.setText(granted ? "ACCESS GRANTED" : "ACCESS DENIED");
        title.setTextSize(40f);
        title.setTextColor(Color.WHITE);
        title.setGravity(Gravity.CENTER);
        title.setTypeface(title.getTypeface(), android.graphics.Typeface.BOLD);
        root.addView(title);

        // Sub-label with reader state if we have one.
        TextView sub = new TextView(this);
        sub.setText(buildSubtitle(granted, readerState));
        sub.setTextSize(16f);
        sub.setTextColor(0xCCFFFFFF); // 80% white
        sub.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        subLp.topMargin = 24;
        sub.setLayoutParams(subLp);
        root.addView(sub);

        // Dismiss button. Big and obvious. The auto-dismiss timer will also
        // close the activity, so this is just for users who want it gone now.
        Button dismiss = new Button(this);
        dismiss.setText("DISMISS");
        dismiss.setOnClickListener(v -> finishAndRemoveTask());
        LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        btnLp.topMargin = 48;
        dismiss.setLayoutParams(btnLp);
        root.addView(dismiss);

        setContentView(root);

        // Auto-dismiss after AUTO_DISMISS_MS unless the user interacts with
        // the dismiss button first. finishAndRemoveTask() is safe to call
        // even if the activity is already finishing.
        new Handler(Looper.getMainLooper()).postDelayed(this::finishAndRemoveTask, AUTO_DISMISS_MS);
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
