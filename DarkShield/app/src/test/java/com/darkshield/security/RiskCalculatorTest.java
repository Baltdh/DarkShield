package com.darkshield.security;

import org.junit.Test;
import java.util.Arrays;
import java.util.Collections;
import static org.junit.Assert.assertEquals;

public class RiskCalculatorTest {

    private ScanFinding finding(ScanFinding.Level level, int points) {
        return new ScanFinding(level, "test", "test", "com.example.test", points, null);
    }

    @Test public void nullAndEmptyAreSafe() {
        assertEquals(0, RiskCalculator.score(null));
        assertEquals(0, RiskCalculator.score(Collections.emptyList()));
        assertEquals("SEM INDICADORES FORTES", RiskCalculator.status(Collections.emptyList()));
    }

    @Test public void scoreIsNormalizedTo100() {
        assertEquals(30, RiskCalculator.score(Arrays.asList(
                finding(ScanFinding.Level.MEDIUM, 10))));
        assertEquals(100, RiskCalculator.score(Arrays.asList(
                finding(ScanFinding.Level.HIGH, 50))));
    }

    @Test public void scoreDoesNotOverflowBeforeCap() {
        assertEquals(100, RiskCalculator.score(Arrays.asList(
                finding(ScanFinding.Level.HIGH, Integer.MAX_VALUE),
                finding(ScanFinding.Level.HIGH, Integer.MAX_VALUE)
        )));
    }

    @Test public void negativeAndNullFindingsDoNotAddRisk() {
        assertEquals(0, RiskCalculator.score(Arrays.asList(
                null,
                finding(ScanFinding.Level.LOW, -10),
                finding(ScanFinding.Level.INFO, 0)
        )));
    }

    @Test public void highestSeverityControlsStatus() {
        assertEquals("RISCO ALTO", RiskCalculator.status(Arrays.asList(
                finding(ScanFinding.Level.LOW, 1),
                finding(ScanFinding.Level.HIGH, 2))));
        assertEquals("RISCO CRÍTICO", RiskCalculator.status(Arrays.asList(
                finding(ScanFinding.Level.HIGH, 2),
                finding(ScanFinding.Level.CRITICAL, 1))));
    }

    @Test public void lowSeverityProducesLowIndicatorStatus() {
        assertEquals("POUCOS INDICADORES", RiskCalculator.status(Arrays.asList(
                finding(ScanFinding.Level.LOW, 1))));
    }

    @Test public void infoDoesNotRaiseStatus() {
        assertEquals("SEM INDICADORES FORTES", RiskCalculator.status(Arrays.asList(
                finding(ScanFinding.Level.INFO, 0))));
    }

    @Test public void nullLevelDoesNotAffectStatus() {
        assertEquals("REVISÃO RECOMENDADA", RiskCalculator.status(Arrays.asList(
                finding(null, 9),
                finding(ScanFinding.Level.MEDIUM, 1)
        )));
        assertEquals("SEM INDICADORES FORTES", RiskCalculator.status(Arrays.asList(
                finding(null, 9)
        )));
    }

    @Test public void nullFindingsDoNotAffectStatus() {
        assertEquals("REVISÃO RECOMENDADA", RiskCalculator.status(Arrays.asList(
                null,
                finding(ScanFinding.Level.MEDIUM, 1)
        )));
    }
}