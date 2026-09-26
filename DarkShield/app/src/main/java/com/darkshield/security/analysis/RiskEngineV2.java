package com.darkshield.security.analysis;

import com.darkshield.security.ScanFinding;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class RiskEngineV2 {
    public enum Confidence { LOW, MEDIUM, HIGH }

    public static final class Assessment {
        public final String packageName;
        public final ScanFinding.Level level;
        public final Confidence confidence;
        public final int riskScore;
        public final int evidenceCount;
        public final int categoryCount;
        public final boolean analysisPartial;

        private Assessment(
                String packageName,
                ScanFinding.Level level,
                Confidence confidence,
                int riskScore,
                int evidenceCount,
                int categoryCount,
                boolean analysisPartial) {
            this.packageName = packageName;
            this.level = level;
            this.confidence = confidence;
            this.riskScore = riskScore;
            this.evidenceCount = evidenceCount;
            this.categoryCount = categoryCount;
            this.analysisPartial = analysisPartial;
        }

        public String summary() {
            return level + " • confiança " + confidence
                    + " • " + evidenceCount + " evidência(s)"
                    + " em " + categoryCount + " categoria(s)"
                    + (analysisPartial ? " • análise parcial" : "");
        }
    }

    private RiskEngineV2() {}

    public static List<Assessment> assess(List<ScanFinding> findings) {
        EvidenceGraph graph = EvidenceGraph.from(findings);
        if (graph.packageNodes().isEmpty()) return Collections.emptyList();

        List<Assessment> assessments = new ArrayList<>();
        for (EvidenceGraph.Node node : graph.packageNodes()) {
            assessments.add(assess(node));
        }

        assessments.sort((left, right) -> {
            int level = Integer.compare(right.level.ordinal(), left.level.ordinal());
            if (level != 0) return level;
            int score = Integer.compare(right.riskScore, left.riskScore);
            if (score != 0) return score;
            int confidence = Integer.compare(
                    right.confidence.ordinal(), left.confidence.ordinal());
            if (confidence != 0) return confidence;
            int name = left.packageName.compareToIgnoreCase(right.packageName);
            return name != 0 ? name : left.packageName.compareTo(right.packageName);
        });
        return Collections.unmodifiableList(assessments);
    }

    static Assessment assess(EvidenceGraph.Node node) {
        int positivePoints = node.positivePoints();
        int categoryCount = node.securityKindCount();
        int evidenceCount = node.evidenceCount();

        int score = Math.min(45, positivePoints * 3);
        if (categoryCount > 1) {
            score += Math.min(20, (categoryCount - 1) * 4);
        }

        boolean correlation = node.has(EvidenceGraph.Kind.CORRELATION);
        boolean active = node.has(EvidenceGraph.Kind.ACTIVE_ACCESS);
        boolean persistence = node.has(EvidenceGraph.Kind.PERSISTENCE);
        boolean remote = node.has(EvidenceGraph.Kind.REMOTE_CONTROL);
        boolean sensitive = node.has(EvidenceGraph.Kind.SENSITIVE_DATA);
        boolean staticAnalysis = node.has(EvidenceGraph.Kind.STATIC_ANALYSIS);
        boolean analysisPartial = node.has(EvidenceGraph.Kind.ANALYSIS_GAP);

        if (correlation) score += 15;
        if (active && persistence && (remote || sensitive)) score += 15;
        if (staticAnalysis && active && (remote || sensitive)) score += 5;
        score = Math.min(100, score);

        Confidence confidence;
        if ((correlation && evidenceCount >= 3 && categoryCount >= 3)
                || (evidenceCount >= 4 && categoryCount >= 4)) {
            confidence = Confidence.HIGH;
        } else if (evidenceCount >= 2 && categoryCount >= 2) {
            confidence = Confidence.MEDIUM;
        } else {
            confidence = Confidence.LOW;
        }

        if (analysisPartial) {
            if (confidence == Confidence.HIGH) confidence = Confidence.MEDIUM;
            else if (confidence == Confidence.MEDIUM) confidence = Confidence.LOW;
        }

        ScanFinding.Level level;
        if (node.strongestLevel() == ScanFinding.Level.CRITICAL && score >= 75) {
            level = ScanFinding.Level.CRITICAL;
        } else if (score >= 65) {
            level = ScanFinding.Level.HIGH;
        } else if (score >= 35) {
            level = ScanFinding.Level.MEDIUM;
        } else if (score >= 15) {
            level = ScanFinding.Level.LOW;
        } else {
            level = ScanFinding.Level.INFO;
        }

        return new Assessment(
                node.packageName,
                level,
                confidence,
                score,
                evidenceCount,
                categoryCount,
                analysisPartial);
    }
}
