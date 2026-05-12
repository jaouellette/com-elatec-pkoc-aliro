package com.psia.pkoc;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.psia.pkoc.core.AliroDiagnosticLog;

import java.util.List;
import java.util.Locale;

/**
 * In-app viewer for the {@link AliroDiagnosticLog} ring buffer.
 *
 * Provides Copy / Share / Clear actions so a user (firmware engineer, tester) can
 * capture the credential's diagnostic output and send it via email, Teams, or any
 * other share-target without having to install adb. The activity auto-refreshes
 * while open if the "Auto" checkbox is set (default).
 */
public class DiagnosticLogActivity extends AppCompatActivity
        implements AliroDiagnosticLog.Listener
{
    private TextView   txtLog;
    private TextView   txtLogCount;
    private ScrollView scrollLog;
    private CheckBox   chkAutoRefresh;
    private Spinner    spinnerLevel;
    private EditText   editFilter;

    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private final Runnable refreshRunnable = this::refresh;

    /** Pending refresh to coalesce bursts of log entries. */
    private boolean refreshScheduled = false;

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_diagnostic_log);

        txtLog         = findViewById(R.id.txtLog);
        txtLogCount    = findViewById(R.id.txtLogCount);
        scrollLog      = findViewById(R.id.scrollLog);
        chkAutoRefresh = findViewById(R.id.chkAutoRefresh);
        spinnerLevel   = findViewById(R.id.spinnerLevel);
        editFilter     = findViewById(R.id.editFilter);

        // Level filter spinner
        ArrayAdapter<String> levelAdapter = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_item,
                new String[]{ "All (V+)", "Debug+", "Info+", "Warn+", "Error only" });
        levelAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerLevel.setAdapter(levelAdapter);
        spinnerLevel.setSelection(1); // default: Debug+
        spinnerLevel.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(android.widget.AdapterView<?> p, View v, int pos, long id) { refresh(); }
            @Override public void onNothingSelected(android.widget.AdapterView<?> p) { }
        });

        editFilter.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(Editable s) { refresh(); }
        });

        Button btnRefresh = findViewById(R.id.btnRefresh);
        Button btnCopy    = findViewById(R.id.btnCopy);
        Button btnShare   = findViewById(R.id.btnShare);
        Button btnClear   = findViewById(R.id.btnClear);

        btnRefresh.setOnClickListener(v -> refresh());
        btnCopy.setOnClickListener(v -> copyToClipboard());
        btnShare.setOnClickListener(v -> shareLog());
        btnClear.setOnClickListener(v -> confirmClear());

        refresh();
    }

    @Override
    protected void onResume()
    {
        super.onResume();
        AliroDiagnosticLog.setListener(this);
        refresh();
    }

    @Override
    protected void onPause()
    {
        super.onPause();
        AliroDiagnosticLog.setListener(null);
        uiHandler.removeCallbacks(refreshRunnable);
    }

    /** Called by AliroDiagnosticLog on any thread when an entry is added or buffer cleared. */
    @Override
    public void onLogChanged()
    {
        if (!chkAutoRefresh.isChecked()) return;
        // Coalesce: schedule at most one refresh per 250 ms.
        synchronized (uiHandler)
        {
            if (refreshScheduled) return;
            refreshScheduled = true;
        }
        uiHandler.postDelayed(() -> {
            synchronized (uiHandler) { refreshScheduled = false; }
            refresh();
        }, 250L);
    }

    // -------------------------------------------------------------------------
    // Rendering
    // -------------------------------------------------------------------------

    private void refresh()
    {
        List<AliroDiagnosticLog.Entry> entries = AliroDiagnosticLog.snapshot();
        int minLevel = spinnerToLevel(spinnerLevel.getSelectedItemPosition());
        String filter = editFilter.getText().toString().trim().toLowerCase(Locale.US);

        StringBuilder sb = new StringBuilder(entries.size() * 80);
        int shown = 0;
        for (AliroDiagnosticLog.Entry e : entries)
        {
            if (e.level < minLevel) continue;
            if (!filter.isEmpty())
            {
                String line = e.formatForShare();
                if (!line.toLowerCase(Locale.US).contains(filter)) continue;
                sb.append(line).append('\n');
            }
            else
            {
                sb.append(e.formatForShare()).append('\n');
            }
            shown++;
        }

        txtLog.setText(sb.toString());
        txtLogCount.setText(shown + " / " + entries.size() + " entries");

        // Auto-scroll to bottom when new entries arrive.
        scrollLog.post(() -> scrollLog.fullScroll(View.FOCUS_DOWN));
    }

    /** Translate Spinner index → AliroDiagnosticLog.LEVEL constant. */
    private static int spinnerToLevel(int spinnerPos)
    {
        switch (spinnerPos)
        {
            case 0: return AliroDiagnosticLog.VERBOSE;
            case 1: return AliroDiagnosticLog.DEBUG;
            case 2: return AliroDiagnosticLog.INFO;
            case 3: return AliroDiagnosticLog.WARN;
            case 4: return AliroDiagnosticLog.ERROR;
            default: return AliroDiagnosticLog.DEBUG;
        }
    }

    // -------------------------------------------------------------------------
    // Actions
    // -------------------------------------------------------------------------

    private void copyToClipboard()
    {
        String text = txtLog.getText().toString();
        if (text.isEmpty())
        {
            toast("Nothing to copy");
            return;
        }
        ClipboardManager cb = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cb.setPrimaryClip(ClipData.newPlainText("Aliro diagnostic log", text));
        toast("Copied " + text.length() + " chars to clipboard");
    }

    private void shareLog()
    {
        String text = txtLog.getText().toString();
        if (text.isEmpty())
        {
            toast("Nothing to share");
            return;
        }
        Intent send = new Intent(Intent.ACTION_SEND);
        send.setType("text/plain");
        send.putExtra(Intent.EXTRA_SUBJECT, "Aliro diagnostic log");
        send.putExtra(Intent.EXTRA_TEXT, text);
        startActivity(Intent.createChooser(send, "Share diagnostic log"));
    }

    private void confirmClear()
    {
        new AlertDialog.Builder(this)
                .setTitle("Clear log")
                .setMessage("Discard all buffered log entries? This cannot be undone.")
                .setPositiveButton("Clear", (d, w) ->
                {
                    AliroDiagnosticLog.clear();
                    refresh();
                    toast("Cleared");
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void toast(String msg)
    {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }
}
