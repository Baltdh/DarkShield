package com.darkshield.security.analysis;

import com.darkshield.security.ScanFinding;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class EvidenceGraphTest {
    private static ScanFinding finding(
            ScanFinding.Level level, String title, String detail, String pkg, int points) {
        return new ScanFinding(level, title, detail, pkg, points, null);
    }

    @Test
    public void separatesGlobalEvidenceAndBuildsDeterministicPackageNodes() {
        List<ScanFinding> findings = Arrays.asList(
                finding(ScanFinding.Level.INFO, "Nível do patch de segurança",
                        "2026-09-05", null, 0),
                finding(ScanFinding.Level.LOW, "Inicialização automática declarada",
                        "boot", "z.pkg", 1),
                finding(ScanFinding.Level.HIGH, "Serviço de acessibilidade ativo",
                        "service", "a.pkg", 8));

        EvidenceGraph graph = EvidenceGraph.from(findings);

        assertEquals(1, graph.globalEvidence().size());
        assertEquals(2, graph.packageNodes().size());
        assertEquals("a.pkg", graph.packageNodes().get(0).packageName);
        assertEquals("z.pkg", graph.packageNodes().get(1).packageName);
    }

    @Test
    public void classifiesIndependentSecurityDimensions() {
        List<ScanFinding> findings = Arrays.asList(
                finding(ScanFinding.Level.HIGH, "Serviço de acessibilidade ativo",
                        "service", "pkg", 8),
                finding(ScanFinding.Level.LOW, "Inicialização automática declarada",
                        "boot", "pkg", 1),
                finding(ScanFinding.Level.MEDIUM, "Acesso a SMS",
                        "operacional", "pkg", 4),
                finding(ScanFinding.Level.LOW, "Código dinâmico combinado com rede",
                        "DEX loader", "pkg", 2));

        EvidenceGraph.Node node = EvidenceGraph.from(findings).packageNodes().get(0);

        assertTrue(node.has(EvidenceGraph.Kind.ACTIVE_ACCESS));
        assertTrue(node.has(EvidenceGraph.Kind.PERSISTENCE));
        assertTrue(node.has(EvidenceGraph.Kind.SENSITIVE_DATA));
        assertTrue(node.has(EvidenceGraph.Kind.STATIC_ANALYSIS));
        assertEquals(4, node.evidenceCount());
        assertEquals(15, node.positivePoints());
        assertEquals(ScanFinding.Level.HIGH, node.strongestLevel());
    }

    @Test
    public void recordsAnalysisGapsWithoutTurningThemIntoThreatCategories() {
        EvidenceGraph.Node node = EvidenceGraph.from(Arrays.asList(
                finding(ScanFinding.Level.LOW, "Falha na análise estática",
                        "Não foi possível ler o APK", "pkg", 1)))
                .packageNodes().get(0);

        assertTrue(node.has(EvidenceGraph.Kind.ANALYSIS_GAP));
        assertEquals(0, node.securityKindCount());
    }
}
