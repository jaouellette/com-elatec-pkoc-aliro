package com.pkoc.readersimulator;

import com.psia.pkoc.core.AliroSelfTestEngine.TestResult;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Generates an HTML compliance report from self-test results.
 * Uses ELATEC brand colors and layout.
 */
public class AliroSelfTestReportGenerator
{
    /**
     * Generate a complete HTML report string.
     *
     * @param results    List of test results
     * @param date       Date string (e.g. "2026-04-08 14:30:00")
     * @param deviceInfo Device info string (e.g. "Samsung Galaxy S24 (Android 15)")
     * @param appVersion App version string
     * @return Complete HTML document as String
     */
    public static String generate(List<TestResult> results, String date,
                                  String deviceInfo, String appVersion)
    {
        int total = results.size();
        int passed = 0, failed = 0, skipped = 0;
        for (TestResult r : results)
        {
            if (r.skipped) skipped++;
            else if (r.passed) passed++;
            else failed++;
        }

        // Group results by their group field
        Map<String, java.util.List<TestResult>> groups = new LinkedHashMap<>();
        for (TestResult r : results)
        {
            groups.computeIfAbsent(r.group, k -> new java.util.ArrayList<>()).add(r);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html>\n<html>\n<head>\n");
        sb.append("  <meta charset=\"UTF-8\">\n");
        sb.append("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        sb.append("  <title>Aliro 1.0 Compliance Report — ELATEC</title>\n");
        sb.append("  <style>\n");
        sb.append("    body { font-family: Arial, sans-serif; color: #1A1A1A; margin: 0; }\n");
        sb.append("    .header { background: #A41D23; color: white; padding: 24px 32px; }\n");
        sb.append("    .header h1 { margin: 0; font-size: 24px; }\n");
        sb.append("    .header p { margin: 4px 0 0; opacity: 0.85; font-size: 14px; }\n");
        sb.append("    .summary { display: flex; gap: 16px; padding: 16px 32px; background: #f5f5f5; }\n");
        sb.append("    .summary-card { flex: 1; border-radius: 8px; padding: 12px; text-align: center; font-size: 20px; font-weight: bold; }\n");
        sb.append("    .summary-label { font-size: 12px; font-weight: normal; margin-top: 4px; }\n");
        sb.append("    .pass-bg { background: #e8f5e9; color: #2E7D32; }\n");
        sb.append("    .fail-bg { background: #ffebee; color: #C62828; }\n");
        sb.append("    .skip-bg { background: #f5f5f5; color: #757575; }\n");
        sb.append("    .total-bg { background: #e3f2fd; color: #1565C0; }\n");
        sb.append("    table { width: calc(100% - 64px); border-collapse: collapse; margin: 0 32px 16px; }\n");
        sb.append("    th { background: #A41D23; color: white; padding: 8px 12px; text-align: left; font-size: 13px; }\n");
        sb.append("    tr:nth-child(even) { background: #fafafa; }\n");
        sb.append("    td { padding: 8px 12px; font-size: 13px; border-bottom: 1px solid #eee; }\n");
        sb.append("    .badge { padding: 2px 8px; border-radius: 12px; font-weight: bold; font-size: 12px; color: white; display: inline-block; }\n");
        sb.append("    .badge-pass { background: #2E7D32; }\n");
        sb.append("    .badge-fail { background: #C62828; }\n");
        sb.append("    .badge-skip { background: #757575; }\n");
        sb.append("    .group-header { background: #7D1519; color: white; padding: 8px 32px; font-weight: bold; margin-top: 16px; font-size: 15px; }\n");
        sb.append("    .detail { color: #6B6B6B; font-size: 12px; margin-top: 2px; }\n");
        sb.append("    .footer { text-align: center; color: #6B6B6B; padding: 24px; font-size: 12px; border-top: 1px solid #eee; margin-top: 16px; }\n");
        sb.append("  </style>\n");
        sb.append("</head>\n<body>\n");

        // Header
        sb.append("  <div class=\"header\">\n");
        sb.append("    <h1>Aliro 1.0 Compliance Report</h1>\n");
        sb.append("    <p>ELATEC Open Standards Simulator &middot; Generated: ").append(esc(date));
        sb.append(" &middot; Device: ").append(esc(deviceInfo));
        if (appVersion != null && !appVersion.isEmpty())
            sb.append(" &middot; v").append(esc(appVersion));
        sb.append("</p>\n  </div>\n");

        // Summary cards
        sb.append("  <div class=\"summary\">\n");
        sb.append("    <div class=\"summary-card pass-bg\">").append(passed).append("<div class=\"summary-label\">Passed</div></div>\n");
        sb.append("    <div class=\"summary-card fail-bg\">").append(failed).append("<div class=\"summary-label\">Failed</div></div>\n");
        sb.append("    <div class=\"summary-card skip-bg\">").append(skipped).append("<div class=\"summary-label\">Skipped</div></div>\n");
        sb.append("    <div class=\"summary-card total-bg\">").append(total).append("<div class=\"summary-label\">Total</div></div>\n");
        sb.append("  </div>\n");

        // Group sections
        for (Map.Entry<String, java.util.List<TestResult>> entry : groups.entrySet())
        {
            String groupName = entry.getKey();
            java.util.List<TestResult> groupResults = entry.getValue();

            int gPassed = 0, gFailed = 0;
            for (TestResult r : groupResults)
            {
                if (r.skipped) continue;
                if (r.passed) gPassed++;
                else gFailed++;
            }

            sb.append("  <div class=\"group-header\">").append(esc(groupName));
            sb.append(" (").append(gPassed).append("/").append(groupResults.size()).append(" passed)");
            sb.append("</div>\n");

            sb.append("  <table>\n");
            sb.append("    <tr><th>Test ID</th><th>Description</th><th>Result</th><th>Duration</th><th>Detail</th></tr>\n");

            for (TestResult r : groupResults)
            {
                sb.append("    <tr>");
                sb.append("<td><code>").append(esc(r.testId)).append("</code></td>");
                sb.append("<td>").append(esc(r.name)).append("</td>");

                String badgeClass = r.skipped ? "badge-skip" : (r.passed ? "badge-pass" : "badge-fail");
                String badgeText = r.skipped ? "SKIP" : (r.passed ? "PASS" : "FAIL");
                sb.append("<td><span class=\"badge ").append(badgeClass).append("\">").append(badgeText).append("</span></td>");

                sb.append("<td>").append(r.durationMs).append("ms</td>");
                sb.append("<td><span class=\"detail\">").append(esc(r.detail != null ? r.detail : "")).append("</span></td>");
                sb.append("</tr>\n");
            }

            sb.append("  </table>\n");
        }

        // Footer
        sb.append("  <div class=\"footer\">\n");
        sb.append("    Generated by ELATEC Open Standards Simulator App &middot; ");
        sb.append("Aliro Specification Test Plan v1.0 &middot; CSA 26-42803-001\n");
        sb.append("  </div>\n");
        sb.append("</body>\n</html>");

        return sb.toString();
    }

    /** HTML-escape a string */
    private static String esc(String s)
    {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
