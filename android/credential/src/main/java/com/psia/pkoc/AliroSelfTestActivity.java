package com.psia.pkoc;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.content.FileProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.psia.pkoc.core.AliroSelfTestEngine;
import com.psia.pkoc.core.AliroSelfTestEngine.TestResult;

import java.io.File;
import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Activity displaying the Aliro 1.0 Self-Test results in a RecyclerView.
 * Accessible via the overflow menu "Aliro Self-Test".
 */
public class AliroSelfTestActivity extends AppCompatActivity
{
    private RecyclerView recyclerTests;
    private Button btnRunTests;
    private Button btnShareReport;
    private ProgressBar progressBar;
    private TestResultAdapter adapter;
    private final List<TestResult> results = new ArrayList<>();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_aliro_self_test);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null)
        {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle("Aliro Self-Test");
        }
        setupViews();
    }

    @Override
    public boolean onCreateOptionsMenu(android.view.Menu menu)
    {
        // Clear any inherited menu items and show no overflow menu
        menu.clear();
        return false;
    }

    @Override
    public boolean onOptionsItemSelected(android.view.MenuItem item)
    {
        if (item.getItemId() == android.R.id.home) { finish(); return true; }
        return super.onOptionsItemSelected(item);
    }

    private void setupViews() {

        recyclerTests = findViewById(R.id.recyclerTests);
        btnRunTests = findViewById(R.id.btnRunTests);
        btnShareReport = findViewById(R.id.btnShareReport);
        progressBar = findViewById(R.id.progressBar);

        adapter = new TestResultAdapter(results);
        recyclerTests.setLayoutManager(new LinearLayoutManager(this));
        recyclerTests.setAdapter(adapter);

        btnRunTests.setOnClickListener(v -> runTests());
        btnShareReport.setOnClickListener(v -> shareReport());
        btnShareReport.setEnabled(false);
    }

    @Override
    public boolean onSupportNavigateUp()
    {
        finish();
        return true;
    }

    private void runTests()
    {
        results.clear();
        adapter.notifyDataSetChanged();
        btnRunTests.setEnabled(false);
        btnShareReport.setEnabled(false);
        progressBar.setVisibility(View.VISIBLE);

        new Thread(() ->
        {
            AliroSelfTestEngine engine = new AliroSelfTestEngine();
            engine.runAll(new AliroSelfTestEngine.Callback()
            {
                @Override
                public void onTestComplete(TestResult result)
                {
                    mainHandler.post(() ->
                    {
                        results.add(result);
                        adapter.notifyItemInserted(results.size() - 1);
                        recyclerTests.scrollToPosition(results.size() - 1);
                    });
                }

                @Override
                public void onAllComplete(List<TestResult> allResults)
                {
                    mainHandler.post(() ->
                    {
                        progressBar.setVisibility(View.GONE);
                        btnRunTests.setEnabled(true);
                        btnShareReport.setEnabled(true);
                    });
                }
            });
        }, "AliroSelfTest").start();
    }

    private void shareReport()
    {
        if (results.isEmpty()) return;

        try
        {
            String deviceInfo = android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL
                    + " (Android " + android.os.Build.VERSION.RELEASE + ")";
            String appVersion = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
            String date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());

            String html = AliroSelfTestReportGenerator.generate(results, date, deviceInfo, appVersion);

            String filename = "aliro_compliance_report_" + System.currentTimeMillis() + ".html";
            File cacheDir = getExternalCacheDir() != null ? getExternalCacheDir() : getCacheDir();
            File reportFile = new File(cacheDir, filename);
            FileWriter writer = new FileWriter(reportFile);
            writer.write(html);
            writer.close();

            Uri uri = FileProvider.getUriForFile(this,
                    getPackageName() + ".fileprovider", reportFile);

            Intent shareIntent = new Intent(Intent.ACTION_SEND);
            shareIntent.setType("application/octet-stream");
            shareIntent.putExtra(Intent.EXTRA_STREAM, uri);
            shareIntent.putExtra(Intent.EXTRA_SUBJECT, "Aliro 1.0 Compliance Report — " + date);
            shareIntent.putExtra(Intent.EXTRA_TEXT, "Aliro 1.0 self-test compliance report attached.");
            shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(shareIntent, "Share Compliance Report"));
        }
        catch (Exception e)
        {
            android.widget.Toast.makeText(this,
                    "Failed to generate report: " + e.getMessage(),
                    android.widget.Toast.LENGTH_LONG).show();
        }
    }

    // =========================================================================
    // RecyclerView Adapter
    // =========================================================================
    private static class TestResultAdapter extends RecyclerView.Adapter<TestResultAdapter.ViewHolder>
    {
        private final List<TestResult> items;

        TestResultAdapter(List<TestResult> items)
        {
            this.items = items;
        }

        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType)
        {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_test_result, parent, false);
            return new ViewHolder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position)
        {
            TestResult r = items.get(position);
            holder.textTestId.setText(r.testId);
            holder.textName.setText(r.name);
            holder.textDuration.setText(r.durationMs + "ms");

            if (r.skipped)
            {
                holder.textResult.setText("SKIP");
                holder.textResult.setBackgroundColor(0xFF757575);
            }
            else if (r.passed)
            {
                holder.textResult.setText("PASS");
                holder.textResult.setBackgroundColor(0xFF2E7D32);
            }
            else
            {
                holder.textResult.setText("FAIL");
                holder.textResult.setBackgroundColor(0xFFC62828);
            }
            holder.textResult.setTextColor(0xFFFFFFFF);

            if (r.detail != null && !r.detail.isEmpty())
            {
                holder.textDetail.setText(r.detail);
                holder.textDetail.setVisibility(View.GONE); // collapsed by default
                holder.itemView.setOnClickListener(v ->
                {
                    boolean visible = holder.textDetail.getVisibility() == View.VISIBLE;
                    holder.textDetail.setVisibility(visible ? View.GONE : View.VISIBLE);
                });
            }
            else
            {
                holder.textDetail.setVisibility(View.GONE);
                holder.itemView.setOnClickListener(null);
            }
        }

        @Override
        public int getItemCount()
        {
            return items.size();
        }

        static class ViewHolder extends RecyclerView.ViewHolder
        {
            TextView textTestId, textName, textResult, textDuration, textDetail;

            ViewHolder(View itemView)
            {
                super(itemView);
                textTestId = itemView.findViewById(R.id.textTestId);
                textName = itemView.findViewById(R.id.textName);
                textResult = itemView.findViewById(R.id.textResult);
                textDuration = itemView.findViewById(R.id.textDuration);
                textDetail = itemView.findViewById(R.id.textDetail);
            }
        }
    }
}
