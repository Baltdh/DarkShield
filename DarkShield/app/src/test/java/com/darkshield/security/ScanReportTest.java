package com.darkshield.security;

import org.junit.Test;
import java.util.ArrayList;
import java.util.List;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ScanReportTest {
    private ScanFinding finding(ScanFinding.Level level, int points) {
        return new ScanFinding(level, "title", "detail", "com.example.test", points, null);
    }

    @Test public void reportCalculatesFromImmutableSnapshot() {
        List<ScanFinding> source = new ArrayList<>();
        source.add(finding(ScanFinding.Level.MEDIUM, 3));

        ScanReport report = new ScanReport(source);
        source.clear();

        assertEquals(1, report.getFindings().size());
        assertEquals(9, report.getScore());
        assertEquals("REVISÃO RECOMENDADA", report.getStatus());
        assertEquals(1, report.count(ScanFinding.Level.MEDIUM));
    }

    @Test public void detailsExcludesInfoFindings() {
        ScanReport report = new ScanReport(java.util.Arrays.asList(
                finding(ScanFinding.Level.INFO, 0),
                finding(ScanFinding.Level.HIGH, 2)));

        String details = report.details();
        assertTrue(details.contains("[HIGH]"));
        assertTrue(!details.contains("[INFO]"));
    }

    @Test public void reviewCountExcludesInfoFindings() {
        ScanReport report = new ScanReport(java.util.Arrays.asList(
                finding(ScanFinding.Level.INFO, 0),
                finding(ScanFinding.Level.MEDIUM, 3),
                finding(ScanFinding.Level.LOW, 1)));

        assertEquals(2, report.countRequiringReview());
    }

    @Test public void detailsSortsBySeverity() {
        ScanReport report = new ScanReport(java.util.Arrays.asList(
                finding(ScanFinding.Level.LOW, 1),
                finding(ScanFinding.Level.CRITICAL, 8),
                finding(ScanFinding.Level.MEDIUM, 3)));

        String details = report.details();
        assertTrue(details.indexOf("[CRITICAL]") < details.indexOf("[MEDIUM]"));
        assertTrue(details.indexOf("[MEDIUM]") < details.indexOf("[LOW]"));
    }

    @Test public void detailsBreaksSeverityTiesDeterministically() {
        ScanReport report = new ScanReport(java.util.Arrays.asList(
                new ScanFinding(ScanFinding.Level.MEDIUM, "B", "detail",
                        "com.example.z", 1, null),
                new ScanFinding(ScanFinding.Level.MEDIUM, "A", "detail",
                        "com.example.a", 3, null),
                new ScanFinding(ScanFinding.Level.MEDIUM, "C", "detail",
                        "com.example.b", 3, null)));

        String details = report.details();
        assertTrue(details.indexOf("com.example.a") < details.indexOf("com.example.b"));
        assertTrue(details.indexOf("com.example.b") < details.indexOf("com.example.z"));
    }

    @Test public void detailsUsesTitleAsFinalTieBreaker() {
        ScanReport report = new ScanReport(java.util.Arrays.asList(
                new ScanFinding(ScanFinding.Level.LOW, "Zeta", "detail",
                        "com.example.same", 1, null),
                new ScanFinding(ScanFinding.Level.LOW, "Alpha", "detail",
                        "com.example.same", 1, null)));

        String details = report.details();
        assertTrue(details.indexOf("Alpha") < details.indexOf("Zeta"));
    }

    @Test public void packageSummariesGroupAndSortFindings() {
        ScanReport report = new ScanReport(java.util.Arrays.asList(
                new ScanFinding(ScanFinding.Level.LOW, "low", "detail",
                        "com.example.b", 1, null),
                new ScanFinding(ScanFinding.Level.HIGH, "high", "detail",
                        "com.example.a", 3, null),
                new ScanFinding(ScanFinding.Level.MEDIUM, "medium", "detail",
                        "com.example.a", 2, null),
                new ScanFinding(ScanFinding.Level.INFO, "info", "detail",
                        "com.example.a", 0, null)));

        List<ScanReport.PackageSummary> summaries = report.packageSummaries();
        assertEquals(2, summaries.size());
        assertEquals("com.example.a", summaries.get(0).packageName);
        assertEquals(ScanFinding.Level.HIGH, summaries.get(0).level);
        assertEquals(2, summaries.get(0).findings);
        assertEquals(5, summaries.get(0).points);
        assertEquals("com.example.b", summaries.get(1).packageName);
    }

    @Test public void packageSummaryShowsTopFiveAndCountsRemaining() {
        java.util.List<ScanFinding> findings = new java.util.ArrayList<>();
        for (int i = 0; i < 6; i++) {
            findings.add(new ScanFinding(
                    ScanFinding.Level.LOW, "finding", "detail",
                    "com.example." + i, 1, null));
        }

        String summary = new ScanReport(findings).packageSummary();
        assertTrue(summary.contains("com.example.0"));
        assertTrue(summary.contains("… e mais 1 pacote(s)"));
    }

    @Test public void detailsShowsHeuristicImpactWhenPointsArePositive() {
        ScanReport report = new ScanReport(java.util.Arrays.asList(
                new ScanFinding(ScanFinding.Level.MEDIUM, "Teste", "detail",
                        "com.example.test", 3, null)));

        String details = report.details();
        assertTrue(details.contains("impacto heurístico: +3 ponto(s)"));
    }


    @Test public void informationalDetailsIncludesInfoAndKeepsThemOutOfReviewDetails() {
        ScanReport report = new ScanReport(java.util.Arrays.asList(
                new ScanFinding(ScanFinding.Level.INFO, "SHA-256 do APK", "ABC123",
                        "com.example.test", 0, null),
                new ScanFinding(ScanFinding.Level.MEDIUM, "review", "detail",
                        "com.example.test", 2, null)));

        String info = report.informationalDetails();
        assertTrue(info.contains("[INFO] SHA-256 do APK"));
        assertTrue(info.contains("ABC123"));
        assertTrue(!report.details().contains("SHA-256 do APK"));
        assertEquals(1, report.countRequiringReview());
    }

    @Test public void nullLevelCountIsZero() {
        ScanReport report = new ScanReport(null);
        assertEquals(0, report.count(null));
        assertEquals(0, report.getScore());
    }
}
