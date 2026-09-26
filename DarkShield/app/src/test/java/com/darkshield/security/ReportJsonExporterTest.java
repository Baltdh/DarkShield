package com.darkshield.security;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.*;

public class ReportJsonExporterTest {
    @Test
    public void redactedExportDoesNotExposeRawPackageOrDetail() {
        ScanFinding finding = new ScanFinding(
                ScanFinding.Level.HIGH,
                "Serviço de acessibilidade ativo",
                "segredo interno com com.example.private",
                "com.example.private",
                8,
                "ação sensível")
                .withEvidence(
                        ScanFinding.EvidenceSource.OBSERVED,
                        ScanFinding.EvidenceTag.ACTIVE_ACCESS);

        ScanReport report = new ScanReport(Collections.singletonList(finding));
        String json = ReportJsonExporter.redacted(
                report,
                Collections.emptyList(),
                123L);

        assertTrue(json.contains("\"package_alias\":\"pkg_"));
        assertFalse(json.contains("com.example.private"));
        assertFalse(json.contains("segredo interno"));
        assertFalse(json.contains("ação sensível"));
        assertTrue(json.contains("\"has_action\":true"));
        assertTrue(json.contains("\"ACTIVE_ACCESS\""));
    }

    @Test
    public void exportIncludesOnlySummaryHistory() {
        ScanHistoryStore.Entry entry =
                new ScanHistoryStore.Entry(100L, 40, 1, 2, 3, 4, 5, 6);

        String json = ReportJsonExporter.redacted(
                new ScanReport(Collections.emptyList()),
                Collections.singletonList(entry),
                200L);

        assertTrue(json.contains("\"history\":[{"));
        assertTrue(json.contains("\"timestamp_millis\":100"));
        assertTrue(json.contains("\"score\":40"));
        assertTrue(json.contains("\"total_findings\":6"));
    }

    @Test
    public void packageAliasIsStableAndDoesNotContainOriginalName() {
        String first = ReportJsonExporter.packageAlias("com.example.app");
        String second = ReportJsonExporter.packageAlias("com.example.app");

        assertEquals(first, second);
        assertTrue(first.startsWith("pkg_"));
        assertFalse(first.contains("com.example.app"));
    }

    @Test
    public void escapeProducesValidJsonEscapes() {
        String escaped = ReportJsonExporter.escape("a\"b\\c\n\t");

        assertEquals("a\\\"b\\\\c\\n\\t", escaped);
    }

    @Test
    public void nullReportStillProducesSchema() {
        String json = ReportJsonExporter.redacted(
                null,
                Arrays.asList((ScanHistoryStore.Entry) null),
                0L);

        assertTrue(json.startsWith("{"));
        assertTrue(json.contains("darkshield.redacted-report.v1"));
        assertTrue(json.endsWith("}"));
    }
}
