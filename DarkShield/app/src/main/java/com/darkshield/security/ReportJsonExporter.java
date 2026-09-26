package com.darkshield.security;

import com.darkshield.security.analysis.RiskEngineV2;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

public final class ReportJsonExporter {
    private ReportJsonExporter() {}

    public static String redacted(
            ScanReport report,
            List<ScanHistoryStore.Entry> history,
            long generatedAtMillis) {
        ScanReport safeReport = report == null
                ? new ScanReport(Collections.emptyList())
                : report;
        List<ScanHistoryStore.Entry> safeHistory = history == null
                ? Collections.emptyList()
                : history;

        StringBuilder out = new StringBuilder(8192);
        out.append('{');
        field(out, "schema", "darkshield.redacted-report.v1");
        comma(out);
        numberField(out, "generated_at_millis", Math.max(0L, generatedAtMillis));
        comma(out);
        numberField(out, "score", safeReport.getScore());
        comma(out);
        numberField(out, "raw_points", safeReport.getRawPoints());
        comma(out);
        numberField(out, "analysis_gaps", safeReport.countAnalysisGaps());
        comma(out);
        field(out, "status", safeReport.getStatus());
        comma(out);

        out.append("\"counts\":{");
        numberField(out, "critical", safeReport.count(ScanFinding.Level.CRITICAL));
        comma(out);
        numberField(out, "high", safeReport.count(ScanFinding.Level.HIGH));
        comma(out);
        numberField(out, "medium", safeReport.count(ScanFinding.Level.MEDIUM));
        comma(out);
        numberField(out, "low", safeReport.count(ScanFinding.Level.LOW));
        comma(out);
        numberField(out, "info", safeReport.count(ScanFinding.Level.INFO));
        comma(out);
        numberField(out, "review", safeReport.countRequiringReview());
        out.append('}');
        comma(out);

        out.append("\"risk_assessments\":[");
        boolean first = true;
        for (RiskEngineV2.Assessment assessment : safeReport.riskAssessmentsV2()) {
            if (assessment == null) continue;
            if (!first) out.append(',');
            first = false;
            out.append('{');
            field(out, "package_alias", packageAlias(assessment.packageName));
            comma(out);
            field(out, "level", value(assessment.level));
            comma(out);
            field(out, "confidence", value(assessment.confidence));
            comma(out);
            numberField(out, "risk_score", assessment.riskScore);
            comma(out);
            numberField(out, "evidence_count", assessment.evidenceCount);
            comma(out);
            numberField(out, "independent_evidence_count", assessment.independentEvidenceCount);
            comma(out);
            numberField(out, "strong_evidence_count", assessment.strongEvidenceCount);
            comma(out);
            numberField(out, "category_count", assessment.categoryCount);
            comma(out);
            booleanField(out, "analysis_partial", assessment.analysisPartial);
            out.append('}');
        }
        out.append(']');
        comma(out);

        out.append("\"findings\":[");
        first = true;
        for (ScanFinding finding : safeReport.getFindings()) {
            if (finding == null) continue;
            if (!first) out.append(',');
            first = false;
            out.append('{');
            field(out, "level", value(finding.level));
            comma(out);
            field(out, "title", finding.title);
            comma(out);
            numberField(out, "points", Math.max(0, finding.points));
            comma(out);
            field(out, "evidence_source", value(finding.evidenceSource));
            comma(out);
            field(out, "package_alias", packageAlias(finding.packageName));
            comma(out);
            booleanField(out, "has_action", finding.action != null && !finding.action.trim().isEmpty());
            comma(out);
            out.append("\"evidence_tags\":[");
            List<String> tags = new ArrayList<>();
            if (finding.evidenceTags != null) {
                for (ScanFinding.EvidenceTag tag : finding.evidenceTags) {
                    if (tag != null) tags.add(tag.name());
                }
            }
            Collections.sort(tags);
            for (int i = 0; i < tags.size(); i++) {
                if (i > 0) out.append(',');
                string(out, tags.get(i));
            }
            out.append(']');
            out.append('}');
        }
        out.append(']');
        comma(out);

        out.append("\"history\":[");
        first = true;
        int count = 0;
        for (ScanHistoryStore.Entry entry : safeHistory) {
            if (entry == null || count >= ScanHistoryStore.MAX_ENTRIES) continue;
            if (!first) out.append(',');
            first = false;
            count++;
            out.append('{');
            numberField(out, "timestamp_millis", entry.timestampMillis);
            comma(out);
            numberField(out, "score", entry.score);
            comma(out);
            numberField(out, "critical", entry.critical);
            comma(out);
            numberField(out, "high", entry.high);
            comma(out);
            numberField(out, "medium", entry.medium);
            comma(out);
            numberField(out, "low", entry.low);
            comma(out);
            numberField(out, "review", entry.reviewCount);
            comma(out);
            numberField(out, "total_findings", entry.totalFindings);
            out.append('}');
        }
        out.append(']');
        out.append('}');
        return out.toString();
    }

    static String packageAlias(String packageName) {
        if (packageName == null || packageName.trim().isEmpty()) return "";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(packageName.getBytes(StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder(12);
            for (int i = 0; i < 6 && i < hash.length; i++) {
                out.append(String.format(Locale.ROOT, "%02x", hash[i]));
            }
            return "pkg_" + out;
        } catch (Exception e) {
            return "pkg_redacted";
        }
    }

    static String escape(String input) {
        if (input == null) return "";
        StringBuilder out = new StringBuilder(input.length() + 16);
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            switch (ch) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (ch < 0x20) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
            }
        }
        return out.toString();
    }

    private static void field(StringBuilder out, String key, String value) {
        string(out, key);
        out.append(':');
        string(out, value == null ? "" : value);
    }

    private static void numberField(StringBuilder out, String key, long value) {
        string(out, key);
        out.append(':').append(value);
    }

    private static void booleanField(StringBuilder out, String key, boolean value) {
        string(out, key);
        out.append(':').append(value ? "true" : "false");
    }

    private static void string(StringBuilder out, String value) {
        out.append('"').append(escape(value)).append('"');
    }

    private static void comma(StringBuilder out) {
        out.append(',');
    }

    private static String value(Object value) {
        return value == null ? "" : value.toString();
    }
}
