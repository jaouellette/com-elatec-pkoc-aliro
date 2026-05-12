package com.psia.pkoc.wearspike;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Bundle;
import android.widget.TextView;

/**
 * Tiny launcher activity for the Wear OS HCE spike.
 *
 * Two purposes:
 *   1. Confirm visually that the APK is installed on the watch (the launcher
 *      icon appears on the watch face).
 *   2. Display the last APDU received by TestHceService, so a tester without
 *      adb access can see real-time evidence that HCE routing worked.
 *
 * No fancy Wear UI library required — a plain TextView in a single layout
 * is enough for the spike. The watch's default theme handles round/square
 * cropping automatically.
 */
public class MainActivity extends Activity
{
    private TextView statusText;

    private final BroadcastReceiver apduReceiver = new BroadcastReceiver()
    {
        @Override
        public void onReceive(Context context, Intent intent)
        {
            if (TestHceService.ACTION_APDU_RECEIVED.equals(intent.getAction()))
            {
                String hex = intent.getStringExtra("apdu_hex");
                if (statusText != null)
                {
                    statusText.setText("APDU received:\n" + hex);
                }
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        statusText = findViewById(R.id.status_text);
    }

    @Override
    protected void onResume()
    {
        super.onResume();
        IntentFilter filter = new IntentFilter(TestHceService.ACTION_APDU_RECEIVED);
        // Tiramisu (API 33) and above require explicit RECEIVER_NOT_EXPORTED
        // for non-system broadcasts. Wear OS 4 ships with API 33+, so this
        // matters even for a watch app.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
        {
            registerReceiver(apduReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        }
        else
        {
            registerReceiver(apduReceiver, filter);
        }
    }

    @Override
    protected void onPause()
    {
        super.onPause();
        try
        {
            unregisterReceiver(apduReceiver);
        }
        catch (IllegalArgumentException ignored)
        {
            // Receiver was never registered (rare race); safe to ignore.
        }
    }
}
