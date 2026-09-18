package com.darkshield.security;

import java.util.List;

public final class RiskCalculator {
    private RiskCalculator() {}

    public static int score(List<ScanFinding> findings) {
        long points = 0;
        if (findings == null) return 0;
        for (ScanFinding finding : findings) {
            if (finding != null) points += Math.max(0, finding.points);
        }
        return (int) Math.min(100L, points * 3L);
    }

    public static int scoreForDisplay(List<ScanFinding> findings) {
        return score(findings);
    }

    public static String status(List<ScanFinding> findings) {
        if (findings == null || findings.isEmpty()) return "SEM INDICADORES FORTES";
        boolean critical = false, high = false, medium = false, low = false;
        for (ScanFinding finding : findings) {
            if (finding == null || finding.level == null) continue;
            switch (finding.level) {
                case CRITICAL: critical = true; break;
                case HIGH: high = true; break;
                case MEDIUM: medium = true; break;
                case LOW: low = true; break;
                default: break;
            }
        }
        if (critical) return "RISCO CRÍTICO";
        if (high) return "RISCO ALTO";
        if (medium) return "REVISÃO RECOMENDADA";
        if (low) return "POUCOS INDICADORES";
        return "SEM INDICADORES FORTES";
    }
}