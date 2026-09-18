package com.darkshield.security;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ScanFindingTest {

    @Test public void lineIncludesPackagePointsAndAction() {
        ScanFinding finding = new ScanFinding(
                ScanFinding.Level.HIGH,
                "Acesso remoto",
                "Indicador detectado",
                "com.example.remote",
                4,
                "Revise o aplicativo");

        String line = finding.line();

        assertTrue(line.contains("[HIGH] Acesso remoto"));
        assertTrue(line.contains("pacote: com.example.remote"));
        assertTrue(line.contains("impacto heurístico: +4 ponto(s)"));
        assertTrue(line.contains("ação: Revise o aplicativo"));
    }

    @Test public void lineDoesNotExposeNonPositiveHeuristicImpact() {
        ScanFinding zero = new ScanFinding(
                ScanFinding.Level.INFO,
                "Informação",
                "Detalhe",
                null,
                0,
                null);
        ScanFinding negative = new ScanFinding(
                ScanFinding.Level.LOW,
                "Falha",
                "Detalhe",
                "com.example.test",
                -3,
                null);

        assertFalse(zero.line().contains("impacto heurístico"));
        assertFalse(negative.line().contains("impacto heurístico"));
    }

    @Test public void lineAllowsMissingOptionalFields() {
        ScanFinding finding = new ScanFinding(
                null, null, null, null, 0, null);

        String line = finding.line();

        assertTrue(line.startsWith("[null] null"));
        assertTrue(line.contains("    null"));
    }
}
