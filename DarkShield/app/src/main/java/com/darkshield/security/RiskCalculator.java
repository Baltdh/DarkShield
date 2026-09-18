package com.darkshield.security;

import java.util.List;

public final class RiskCalculator {
    private RiskCalculator() {}

    public static int score(List<ScanFinding> findings) {
        int points = 0;
        if (findings == null) return 0;
        for (ScanFinding finding : findings) {
            if (finding != null) points += Math.max(0, finding.points);
        }
        return Math.min(100, points * 3);
    }

    public static String status(List<ScanFinding> findings) {
        if (findings == null || findings.isEmpty()) return "SEM INDICADORES FORTES";
        boolean critical = false, high = false, medium = false, low = false;
        for (ScanFinding finding : findings) {
            if (finding == null) continue;
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