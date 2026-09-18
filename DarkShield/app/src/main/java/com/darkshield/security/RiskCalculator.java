package com.darkshield.security;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class RiskCalculator {
    private static final int MAX_POINTS_PER_PACKAGE = 15;
    private RiskCalculator() {}

    public static int score(List<ScanFinding> findings) {
        if (findings == null || findings.isEmpty()) return 0;

        long points = 0;
        Map<String, Integer> packagePoints = new HashMap<>();
        int globalPoints = 0;

        for (ScanFinding finding : findings) {
            if (finding == null) continue;
            int candidate = Math.max(0, finding.points);
            if (candidate == 0) continue;

            if (finding.packageName == null || finding.packageName.trim().isEmpty()) {
                globalPoints += candidate;
                continue;
            }

            String packageName = finding.packageName;
            int current = packagePoints.getOrDefault(packageName, 0);
            int accepted = Math.min(candidate, MAX_POINTS_PER_PACKAGE - current);
            if (accepted > 0) packagePoints.put(packageName, current + accepted);
        }

        for (int value : packagePoints.values()) points += value;
        points += globalPoints;
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
