package com.darkshield.security;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class RiskCalculator {
    private static final int MAX_POINTS_PER_PACKAGE = 15;
    private static final int MAX_DERIVED_POINTS_PER_PACKAGE = 2;
    private static final int MAX_GLOBAL_DERIVED_POINTS = 2;

    private RiskCalculator() {}

    public static int score(List<ScanFinding> findings) {
        if (findings == null || findings.isEmpty()) return 0;

        long points = 0L;
        Map<String, Integer> packagePoints = new HashMap<>();
        Map<String, Integer> derivedPackagePoints = new HashMap<>();
        long globalPoints = 0L;
        int globalDerivedPoints = 0;

        for (ScanFinding finding : findings) {
            if (finding == null) continue;
            int candidate = Math.max(0, finding.points);
            if (candidate == 0) continue;

            boolean derived =
                    finding.evidenceSource == ScanFinding.EvidenceSource.DERIVED;
            boolean global =
                    finding.packageName == null || finding.packageName.trim().isEmpty();

            if (derived) {
                if (global) {
                    int remaining = MAX_GLOBAL_DERIVED_POINTS - globalDerivedPoints;
                    if (remaining > 0) {
                        globalDerivedPoints += Math.min(candidate, remaining);
                    }
                    continue;
                }

                String packageName = finding.packageName;
                int current = derivedPackagePoints.getOrDefault(packageName, 0);
                int remaining = MAX_DERIVED_POINTS_PER_PACKAGE - current;
                if (remaining > 0) {
                    derivedPackagePoints.put(
                            packageName,
                            current + Math.min(candidate, remaining));
                }
                continue;
            }

            if (global) {
                globalPoints += candidate;
                continue;
            }

            String packageName = finding.packageName;
            int current = packagePoints.getOrDefault(packageName, 0);
            int accepted = Math.min(candidate, MAX_POINTS_PER_PACKAGE - current);
            if (accepted > 0) packagePoints.put(packageName, current + accepted);
        }

        for (int value : packagePoints.values()) points += value;
        for (int value : derivedPackagePoints.values()) points += value;
        points += globalPoints;
        points += globalDerivedPoints;
        return (int) Math.min(100L, points * 3L);
    }

    public static int scoreForDisplay(List<ScanFinding> findings) {
        return score(findings);
    }

    public static String status(List<ScanFinding> findings) {
        if (findings == null || findings.isEmpty()) return "SEM INDICADORES FORTES";

        boolean critical = false;
        boolean high = false;
        boolean medium = false;
        boolean low = false;
        boolean derivedReview = false;

        for (ScanFinding finding : findings) {
            if (finding == null || finding.level == null) continue;

            if (finding.evidenceSource == ScanFinding.EvidenceSource.DERIVED) {
                if (finding.level != ScanFinding.Level.INFO) derivedReview = true;
                continue;
            }

            switch (finding.level) {
                case CRITICAL:
                    critical = true;
                    break;
                case HIGH:
                    high = true;
                    break;
                case MEDIUM:
                    medium = true;
                    break;
                case LOW:
                    low = true;
                    break;
                default:
                    break;
            }
        }

        if (critical) return "RISCO CRÍTICO";
        if (high) return "RISCO ALTO";
        if (medium) return "REVISÃO RECOMENDADA";
        if (low) return "POUCOS INDICADORES";
        if (derivedReview) return "MUDANÇA PARA REVISAR";
        return "SEM INDICADORES FORTES";
    }
}
