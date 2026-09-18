package com.darkshield.security;

import org.junit.Test;
import java.util.Arrays;
import static org.junit.Assert.assertEquals;

public class RiskCalculatorTest {
    @Test public void scoreCapsRepeatedFindingsForOnePackage() {
        ScanFinding[] findings = new ScanFinding[10];
        for (int i = 0; i < findings.length; i++) {
            findings[i] = new ScanFinding(
                    ScanFinding.Level.MEDIUM, "signal-" + i, "detail",
                    "com.example.app", 4, null);
        }
        assertEquals(45, RiskCalculator.score(Arrays.asList(findings)));
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
}
