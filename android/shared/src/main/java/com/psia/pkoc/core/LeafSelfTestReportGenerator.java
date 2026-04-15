package com.psia.pkoc.core;

import com.psia.pkoc.core.LeafSelfTestEngine.TestResult;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Generates an HTML LEAF Verified Compliance Report from self-test results.
 *
 * Uses ELATEC brand color (#A41D23) and the same table/badge layout as the
 * Aliro Compliance Report, adapted for LEAF Verified branding.
 *
 * Designed to be shared as a self-contained HTML file via Android's
 * {@link android.content.Intent#ACTION_SEND} share sheet.
 */
public class LeafSelfTestReportGenerator
{
    /**
     * Generate a complete HTML report string.
     *
     * @param results    List of LEAF self-test results
     * @param date       Date string (e.g. "2026-04-08 14:30:00")
     * @param deviceInfo Device info string (e.g. "Google Pixel 9 (Android 15)")
     * @param appVersion App version string (may be null)
     * @return Complete HTML document as String
     */
    public static String generate(List<TestResult> results, String date,
                                  String deviceInfo, String appVersion)
    {
        int total = results.size();
        int passed = 0, failed = 0, skipped = 0;
        for (TestResult r : results)
        {
            if (r.skipped)      skipped++;
            else if (r.passed)  passed++;
            else                failed++;
        }

        // Group results by their group field (preserving insertion order)
        Map<String, List<TestResult>> groups = new LinkedHashMap<>();
        for (TestResult r : results)
        {
            groups.computeIfAbsent(r.group, k -> new ArrayList<>()).add(r);
        }

        StringBuilder sb = new StringBuilder(8192);
        sb.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        sb.append("  <meta charset=\"UTF-8\">\n");
        sb.append("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        sb.append("  <title>LEAF Verified Compliance Report — ELATEC</title>\n");
        sb.append("  <style>\n");
        sb.append("    body { font-family: Arial, sans-serif; color: #1A1A1A; margin: 0; padding: 0; }\n");
        sb.append("    .header { background: #A41D23; color: white; padding: 24px 32px; }\n");
        sb.append("    .header h1 { margin: 0 0 4px; font-size: 22px; }\n");
        sb.append("    .header .subtitle { font-size: 13px; opacity: 0.85; margin: 0; }\n");
        sb.append("    .header .leaf-badge { display: inline-block; background: rgba(255,255,255,0.18); border: 1px solid rgba(255,255,255,0.4); border-radius: 4px; padding: 2px 10px; font-size: 12px; font-weight: bold; margin-bottom: 8px; letter-spacing: 0.05em; }\n");
        sb.append("    .summary { display: flex; gap: 12px; padding: 16px 32px; background: #f5f5f5; flex-wrap: wrap; }\n");
        sb.append("    .summary-card { flex: 1; min-width: 80px; border-radius: 8px; padding: 12px 8px; text-align: center; font-size: 22px; font-weight: bold; }\n");
        sb.append("    .summary-label { font-size: 11px; font-weight: normal; margin-top: 4px; }\n");
        sb.append("    .pass-bg  { background: #e8f5e9; color: #2E7D32; }\n");
        sb.append("    .fail-bg  { background: #ffebee; color: #C62828; }\n");
        sb.append("    .skip-bg  { background: #f5f5f5; color: #757575; border: 1px solid #e0e0e0; }\n");
        sb.append("    .total-bg { background: #e3f2fd; color: #1565C0; }\n");
        sb.append("    .group-header { background: #7D1519; color: white; padding: 8px 32px; font-weight: bold; margin-top: 16px; font-size: 14px; letter-spacing: 0.03em; }\n");
        sb.append("    table { width: calc(100% - 64px); border-collapse: collapse; margin: 0 32px 8px; }\n");
        sb.append("    th { background: #A41D23; color: white; padding: 8px 12px; text-align: left; font-size: 12px; white-space: nowrap; }\n");
        sb.append("    tr:nth-child(even) { background: #fafafa; }\n");
        sb.append("    td { padding: 7px 12px; font-size: 12px; border-bottom: 1px solid #eee; vertical-align: top; }\n");
        sb.append("    code { font-family: monospace; font-size: 11px; color: #4A0000; }\n");
        sb.append("    .badge { padding: 2px 8px; border-radius: 12px; font-weight: bold; font-size: 11px; color: white; display: inline-block; white-space: nowrap; }\n");
        sb.append("    .badge-pass { background: #2E7D32; }\n");
        sb.append("    .badge-fail { background: #C62828; }\n");
        sb.append("    .badge-skip { background: #757575; }\n");
        sb.append("    .detail { color: #6B6B6B; font-size: 11px; font-family: monospace; }\n");
        sb.append("    .meta { padding: 8px 32px 0; font-size: 12px; color: #555; }\n");
        sb.append("    .footer { text-align: center; color: #6B6B6B; padding: 24px 32px; font-size: 11px; border-top: 1px solid #eee; margin-top: 16px; }\n");
        sb.append("    @media (max-width: 600px) { table { width: 100%; margin: 0 0 8px; } .group-header { padding: 8px 16px; } .meta { padding: 8px 16px 0; } .summary { padding: 12px 16px; } .header { padding: 16px; } }\n");
        sb.append("  </style>\n");
        sb.append("</head>\n<body>\n");

        // ---- Header ----
        sb.append("  <div class=\"header\">\n");
        sb.append("    <div class=\"leaf-badge\">LEAF Verified</div>\n");
        sb.append("    <h1>LEAF Verified Compliance Report</h1>\n");
        sb.append("    <p class=\"subtitle\">");
        sb.append("ELATEC Reader Simulator &middot; Generated: ").append(esc(date));
        if (deviceInfo != null && !deviceInfo.isEmpty())
            sb.append(" &middot; ").append(esc(deviceInfo));
        if (appVersion != null && !appVersion.isEmpty())
            sb.append(" &middot; v").append(esc(appVersion));
        sb.append("</p>\n  </div>\n");

        // ---- Summary cards ----
        sb.append("  <div class=\"summary\">\n");
        sb.append("    <div class=\"summary-card pass-bg\">").append(passed)
          .append("<div class=\"summary-label\">Passed</div></div>\n");
        sb.append("    <div class=\"summary-card fail-bg\">").append(failed)
          .append("<div class=\"summary-label\">Failed</div></div>\n");
        sb.append("    <div class=\"summary-card skip-bg\">").append(skipped)
          .append("<div class=\"summary-label\">Skipped</div></div>\n");
        sb.append("    <div class=\"summary-card total-bg\">").append(total)
          .append("<div class=\"summary-label\">Total</div></div>\n");
        sb.append("  </div>\n");

        // ---- Overall pass/fail banner ----
        sb.append("  <div class=\"meta\">");
        if (failed == 0 && total > 0)
            sb.append("<strong style=\"color:#2E7D32;\">&#10003; ALL TESTS PASSED</strong> — Device meets LEAF Verified protocol requirements.");
        else if (failed > 0)
            sb.append("<strong style=\"color:#C62828;\">&#10007; " + failed + " TEST(S) FAILED</strong> — See details below.");
        else
            sb.append("No tests run.");
        sb.append("</div>\n");

        // ---- Group sections ----
        for (Map.Entry<String, List<TestResult>> entry : groups.entrySet())
        {
            String groupName    = entry.getKey();
            List<TestResult> gr = entry.getValue();

            int gPassed = 0, gFailed = 0, gSkipped = 0;
            for (TestResult r : gr)
            {
                if (r.skipped)     gSkipped++;
                else if (r.passed) gPassed++;
                else               gFailed++;
            }

            sb.append("  <div class=\"group-header\">")
              .append(esc(groupName))
              .append(" &mdash; ")
              .append(gPassed).append("/").append(gr.size()).append(" passed");
            if (gSkipped > 0) sb.append(" (").append(gSkipped).append(" skipped)");
            sb.append("</div>\n");

            sb.append("  <table>\n");
            sb.append("    <tr><th>Test ID</th><th>Description</th><th>Result</th><th>Duration</th><th>Detail</th></tr>\n");

            for (TestResult r : gr)
            {
                sb.append("    <tr>");
                sb.append("<td><code>").append(esc(r.testId)).append("</code></td>");
                sb.append("<td>").append(esc(r.name)).append("</td>");

                String badgeClass = r.skipped ? "badge-skip" : (r.passed ? "badge-pass" : "badge-fail");
                String badgeText  = r.skipped ? "SKIP"       : (r.passed ? "PASS"       : "FAIL");
                sb.append("<td><span class=\"badge ").append(badgeClass).append("\">")
                  .append(badgeText).append("</span></td>");

                sb.append("<td>").append(r.durationMs).append("ms</td>");
                sb.append("<td><span class=\"detail\">").append(esc(r.detail != null ? r.detail : "")).append("</span></td>");
                sb.append("</tr>\n");
            }

            sb.append("  </table>\n");
        }

        // ---- Footer ----
        sb.append("  <div class=\"footer\">\n");
        sb.append("    Generated by ELATEC PKOC/Aliro Reader Simulator &middot; ");
        sb.append("LEAF Verified Open ID Protocol &middot; Path 1 (ISO 7816 / HCE)\n");
        sb.append("  </div>\n");
        sb.append("</body>\n</html>");

        return sb.toString();
    }

    /** HTML-escape a string. */
    private static String esc(String s)
    {
        if (s == null) return "";
        return s.replace("&",  "&amp;")
                .replace("<",  "&lt;")
                .replace(">",  "&gt;")
                .replace("\"", "&quot;");
    }
}
