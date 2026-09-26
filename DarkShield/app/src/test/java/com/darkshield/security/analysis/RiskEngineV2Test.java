package com.darkshield.security.analysis;

import com.darkshield.security.ScanFinding;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class RiskEngineV2Test {
    private static ScanFinding finding(
            ScanFinding.Level level, String title, String detail, String pkg, int points) {
        return new ScanFinding(level, title, detail, pkg, points, null);
    }

    @Test
    public void emptyInputProducesNoAssessments() {
        assertTrue(RiskEngineV2.assess(Collections.emptyList()).isEmpty());
    }

    @Test
    public void isolatedWeakSignalKeepsLowConfidence() {
        List<RiskEngineV2.Assessment> assessments = RiskEngineV2.assess(Arrays.asList(
                finding(ScanFinding.Level.LOW, "Inicialização automática declarada",
                        "boot", "pkg", 1)));

        assertEquals(1, assessments.size());
        assertEquals(RiskEngineV2.Confidence.LOW, assessments.get(0).confidence);
        assertTrue(assessments.get(0).riskScore < 35);
    }

    @Test
    public void correlatedMultiCategoryChainRaisesRiskAndConfidence() {
        List<RiskEngineV2.Assessment> assessments = RiskEngineV2.assess(Arrays.asList(
                finding(ScanFinding.Level.HIGH, "Serviço de acessibilidade ativo",
                        "service", "pkg", 8),
                finding(ScanFinding.Level.LOW, "Inicialização automática declarada",
                        "boot", "pkg", 1),
                finding(ScanFinding.Level.MEDIUM, "Acesso a SMS",
                        "operacional", "pkg", 4),
                finding(ScanFinding.Level.HIGH,
                        "Correlação de acessibilidade, notificações e boot",
                        "combinação de sinais", "pkg", 7)));

        RiskEngineV2.Assessment assessment = assessments.get(0);
        assertEquals(ScanFinding.Level.HIGH, assessment.level);
        assertEquals(RiskEngineV2.Confidence.HIGH, assessment.confidence);
        assertTrue(assessment.riskScore >= 65);
        assertTrue(assessment.categoryCount >= 4);
    }

    @Test
    public void incompleteAnalysisDowngradesConfidence() {
        List<RiskEngineV2.Assessment> assessments = RiskEngineV2.assess(Arrays.asList(
                finding(ScanFinding.Level.HIGH, "Serviço de acessibilidade ativo",
                        "service", "pkg", 8),
                finding(ScanFinding.Level.LOW, "Inicialização automática declarada",
                        "boot", "pkg", 1),
                finding(ScanFinding.Level.MEDIUM, "Acesso a SMS",
                        "operacional", "pkg", 4),
                finding(ScanFinding.Level.HIGH,
                        "Correlação de acessibilidade, notificações e boot",
                        "combinação de sinais", "pkg", 7),
                finding(ScanFinding.Level.LOW, "Falha na análise estática",
                        "Não foi possível ler parte do APK", "pkg", 1)));

        RiskEngineV2.Assessment assessment = assessments.get(0);
        assertTrue(assessment.analysisPartial);
        assertEquals(RiskEngineV2.Confidence.MEDIUM, assessment.confidence);
        assertTrue(assessment.riskScore <= 100);
    }
    @Test
    public void structuredRemoteChainRaisesRiskWithoutTextMarkers() {
        List<RiskEngineV2.Assessment> assessments = RiskEngineV2.assess(Arrays.asList(
                new ScanFinding(ScanFinding.Level.HIGH, "A", "x", "pkg", 8, null)
                        .withTags(ScanFinding.EvidenceTag.ACTIVE_ACCESS),
                new ScanFinding(ScanFinding.Level.LOW, "B", "y", "pkg", 1, null)
                        .withTags(ScanFinding.EvidenceTag.PERSISTENCE),
                new ScanFinding(ScanFinding.Level.MEDIUM, "C", "z", "pkg", 4, null)
                        .withTags(ScanFinding.EvidenceTag.REMOTE_CONTROL),
                new ScanFinding(ScanFinding.Level.HIGH, "D", "w", "pkg", 7, null)
                        .withTags(ScanFinding.EvidenceTag.CORRELATION)));

        RiskEngineV2.Assessment assessment = assessments.get(0);
        assertEquals(ScanFinding.Level.HIGH, assessment.level);
        assertEquals(RiskEngineV2.Confidence.HIGH, assessment.confidence);
        assertTrue(assessment.riskScore >= 65);
    }
    @Test
    public void declaredAndHeuristicOnlyEvidenceCannotReachHighConfidence() {
        List<RiskEngineV2.Assessment> assessments = RiskEngineV2.assess(Arrays.asList(
                new ScanFinding(ScanFinding.Level.MEDIUM, "A", "x", "pkg", 5, null)
                        .withEvidence(
                                ScanFinding.EvidenceSource.DECLARED,
                                ScanFinding.EvidenceTag.PERSISTENCE),
                new ScanFinding(ScanFinding.Level.MEDIUM, "B", "y", "pkg", 5, null)
                        .withEvidence(
                                ScanFinding.EvidenceSource.HEURISTIC,
                                ScanFinding.EvidenceTag.REMOTE_CONTROL),
                new ScanFinding(ScanFinding.Level.HIGH, "C", "z", "pkg", 7, null)
                        .withEvidence(
                                ScanFinding.EvidenceSource.DERIVED,
                                ScanFinding.EvidenceTag.CORRELATION)));

        RiskEngineV2.Assessment assessment = assessments.get(0);
        assertEquals(RiskEngineV2.Confidence.LOW, assessment.confidence);
        assertEquals(0, assessment.strongEvidenceCount);
        assertEquals(2, assessment.independentEvidenceCount);
    }

    @Test
    public void observedEvidenceCanRaiseConfidenceWithIndependentCategories() {
        List<RiskEngineV2.Assessment> assessments = RiskEngineV2.assess(Arrays.asList(
                new ScanFinding(ScanFinding.Level.HIGH, "A", "x", "pkg", 8, null)
                        .withEvidence(
                                ScanFinding.EvidenceSource.OBSERVED,
                                ScanFinding.EvidenceTag.ACTIVE_ACCESS),
                new ScanFinding(ScanFinding.Level.MEDIUM, "B", "y", "pkg", 4, null)
                        .withEvidence(
                                ScanFinding.EvidenceSource.OBSERVED,
                                ScanFinding.EvidenceTag.SENSITIVE_DATA),
                new ScanFinding(ScanFinding.Level.LOW, "C", "z", "pkg", 1, null)
                        .withEvidence(
                                ScanFinding.EvidenceSource.DECLARED,
                                ScanFinding.EvidenceTag.PERSISTENCE),
                new ScanFinding(ScanFinding.Level.HIGH, "D", "w", "pkg", 7, null)
                        .withEvidence(
                                ScanFinding.EvidenceSource.DERIVED,
                                ScanFinding.EvidenceTag.CORRELATION)));

        RiskEngineV2.Assessment assessment = assessments.get(0);
        assertEquals(RiskEngineV2.Confidence.HIGH, assessment.confidence);
        assertEquals(2, assessment.strongEvidenceCount);
        assertEquals(3, assessment.independentEvidenceCount);
    }
}
