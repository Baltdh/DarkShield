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

    @Test public void nullLevelCountIsZero() {
        ScanReport report = new ScanReport(null);
        assertEquals(0, report.count(null));
        assertEquals(0, report.getScore());
    }
}
