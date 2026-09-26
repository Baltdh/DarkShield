package com.darkshield.security;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SecurityStateScannerTest {
    @Test
    public void nullContextProducesNoFindings() {
        assertTrue(SecurityStateScanner.scan(null).isEmpty());
    }

    @Test
    public void unavailableStateIsInformationalAndDoesNotIncreaseRisk() {
        ScanFinding finding = SecurityStateScanner.unavailable(
                "Estado de patch — kernel",
                "Consulta indisponível");

        assertEquals(ScanFinding.Level.INFO, finding.level);
        assertEquals(0, finding.points);
        assertTrue(finding.detail.contains("não deve ser interpretada"));
    }
}
