package com.darkshield.security;

import org.junit.Test;
import java.util.Arrays;
import java.util.Collections;
import static org.junit.Assert.assertEquals;

public class RiskCalculatorTest {

    private ScanFinding finding(ScanFinding.Level level, int points) {
        return new ScanFinding(level, "test", "test", "com.example.test", points, null);
    }

    private ScanFinding finding(ScanFinding.Level level, int points, String packageName) {
        return new ScanFinding(level, "test", "test", packageName, points, null);
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
                finding(ScanFinding.Level.HIGH, 50, "com.example.one"),
                finding(ScanFinding.Level.HIGH, 50, "com.example.two"),
                finding(ScanFinding.Level.HIGH, 50, "com.example.three"))));
    }

    @Test public void scoreDoesNotOverflowBeforeCap() {
        assertEquals(100, RiskCalculator.score(Arrays.asList(
                finding(ScanFinding.Level.HIGH, Integer.MAX_VALUE, "com.example.one"),
                finding(ScanFinding.Level.HIGH, Integer.MAX_VALUE, "com.example.two"),
                finding(ScanFinding.Level.HIGH, Integer.MAX_VALUE, "com.example.three")
        )));
    }

    @Test public void globalPointsDoNotOverflowBeforeCap() {
        ScanFinding first = new ScanFinding(
                ScanFinding.Level.HIGH, "global-one", "detail",
                null, Integer.MAX_VALUE, null);
        ScanFinding second = new ScanFinding(
                ScanFinding.Level.HIGH, "global-two", "detail",
                null, Integer.MAX_VALUE, null);
        assertEquals(100, RiskCalculator.score(Arrays.asList(first, second)));
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

    @Test public void scoreForDisplayDelegatesToScoreContract() {
        assertEquals(RiskCalculator.score(Arrays.asList(
                finding(ScanFinding.Level.HIGH, 40),
                finding(ScanFinding.Level.LOW, 1))),
                RiskCalculator.scoreForDisplay(Arrays.asList(
                        finding(ScanFinding.Level.HIGH, 40),
                        finding(ScanFinding.Level.LOW, 1))));
        assertEquals(RiskCalculator.score(null), RiskCalculator.scoreForDisplay(null));
    }

    @Test public void scoreCapsRepeatedFindingsForOnePackage() {
        ScanFinding[] findings = new ScanFinding[10];
        for (int i = 0; i < findings.length; i++) {
            findings[i] = new ScanFinding(
                    ScanFinding.Level.MEDIUM, "signal-" + i, "detail",
                    "com.example.app", 4, null);
        }
        assertEquals(45, RiskCalculator.score(Arrays.asList(findings)));
    }

    @Test public void packageCapIsExactlyFifteenPoints() {
        assertEquals(45, RiskCalculator.score(Arrays.asList(
                finding(ScanFinding.Level.HIGH, 15, "com.example.app"),
                finding(ScanFinding.Level.MEDIUM, 1, "com.example.app"))));
    }

    @Test public void scoreKeepsIndependentPackagesSeparate() {
        ScanFinding first = new ScanFinding(
                ScanFinding.Level.MEDIUM, "signal", "detail",
                "com.example.one", 10, null);
        ScanFinding second = new ScanFinding(
                ScanFinding.Level.MEDIUM, "signal", "detail",
                "com.example.two", 10, null);
        assertEquals(60, RiskCalculator.score(Arrays.asList(first, second)));
    }

    @Test public void informationalFindingsDoNotChangeScore() {
        ScanFinding info = new ScanFinding(
                ScanFinding.Level.INFO, "info", "detail",
                "com.example.app", 0, null);
        assertEquals(0, RiskCalculator.score(Arrays.asList(info)));
    }

    @Test public void globalFindingsAreNotGroupedByPackage() {
        ScanFinding first = new ScanFinding(
                ScanFinding.Level.HIGH, "global-one", "detail",
                null, 10, null);
        ScanFinding second = new ScanFinding(
                ScanFinding.Level.HIGH, "global-two", "detail",
                null, 10, null);
        assertEquals(60, RiskCalculator.score(Arrays.asList(first, second)));
    }

    @Test public void blankPackageNameUsesGlobalRiskBucket() {
        assertEquals(60, RiskCalculator.score(Arrays.asList(
                finding(ScanFinding.Level.MEDIUM, 10, " "),
                finding(ScanFinding.Level.MEDIUM, 10, "	"))));
    }
    @Test public void derivedPointsAreBoundedPerPackage() {
        ScanFinding observed = new ScanFinding(
                ScanFinding.Level.LOW,
                "observed",
                "x",
                "com.example.app",
                1,
                null)
                .withEvidence(
                        ScanFinding.EvidenceSource.OBSERVED,
                        ScanFinding.EvidenceTag.PERSISTENCE);
        ScanFinding derivedOne = new ScanFinding(
                ScanFinding.Level.HIGH,
                "derived-one",
                "x",
                "com.example.app",
                50,
                null)
                .withEvidence(
                        ScanFinding.EvidenceSource.DERIVED,
                        ScanFinding.EvidenceTag.CORRELATION);
        ScanFinding derivedTwo = new ScanFinding(
                ScanFinding.Level.HIGH,
                "derived-two",
                "x",
                "com.example.app",
                50,
                null)
                .withEvidence(
                        ScanFinding.EvidenceSource.DERIVED,
                        ScanFinding.EvidenceTag.CORRELATION);

        assertEquals(9, RiskCalculator.score(Arrays.asList(
                observed, derivedOne, derivedTwo)));
    }

    @Test public void derivedOnlyFindingDoesNotClaimHighOverallRisk() {
        ScanFinding derived = new ScanFinding(
                ScanFinding.Level.HIGH,
                "temporal change",
                "x",
                "com.example.app",
                50,
                null)
                .withEvidence(
                        ScanFinding.EvidenceSource.DERIVED,
                        ScanFinding.EvidenceTag.CORRELATION);

        assertEquals(6, RiskCalculator.score(Arrays.asList(derived)));
        assertEquals(
                "MUDANÇA PARA REVISAR",
                RiskCalculator.status(Arrays.asList(derived)));
    }

    @Test public void globalDerivedPointsAreBounded() {
        ScanFinding first = new ScanFinding(
                ScanFinding.Level.HIGH,
                "derived-global-one",
                "x",
                null,
                50,
                null)
                .withEvidence(
                        ScanFinding.EvidenceSource.DERIVED,
                        ScanFinding.EvidenceTag.CORRELATION);
        ScanFinding second = new ScanFinding(
                ScanFinding.Level.HIGH,
                "derived-global-two",
                "x",
                null,
                50,
                null)
                .withEvidence(
                        ScanFinding.EvidenceSource.DERIVED,
                        ScanFinding.EvidenceTag.CORRELATION);

        assertEquals(6, RiskCalculator.score(Arrays.asList(first, second)));
    }

}
