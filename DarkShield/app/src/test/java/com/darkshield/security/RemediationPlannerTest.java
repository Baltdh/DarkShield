package com.darkshield.security;

import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

public class RemediationPlannerTest {
    @Test public void highFindingCreatesSafeReviewAction() {
        ScanFinding finding = new ScanFinding(
                ScanFinding.Level.HIGH,
                "Serviço de acessibilidade ativo",
                "Serviço desconhecido",
                "com.example.suspicious",
                8,
                "Revise");
        List<RemediationPlanner.Action> actions =
                RemediationPlanner.plan(Arrays.asList(finding));

        assertEquals(1, actions.size());
        assertEquals("com.example.suspicious", actions.get(0).packageName);
        assertEquals(RemediationPlanner.Kind.ACCESSIBILITY, actions.get(0).kind);
        assertTrue(actions.get(0).title.contains("acessibilidade"));
    }

    @Test public void infoFindingDoesNotCreateCorrection() {
        ScanFinding finding = new ScanFinding(
                ScanFinding.Level.INFO,
                "Acesso a contatos",
                "Uso normal",
                "com.example.normal",
                0,
                null);
        assertTrue(RemediationPlanner.plan(Arrays.asList(finding)).isEmpty());
    }

    @Test public void differentGrantsOnSameAppRemainSeparate() {
        List<RemediationPlanner.Action> actions = RemediationPlanner.plan(Arrays.asList(
                new ScanFinding(ScanFinding.Level.MEDIUM, "Acesso aos dados de uso", "Uso",
                        "com.example.app", 3, null),
                new ScanFinding(ScanFinding.Level.LOW, "Permissão de sobreposição concedida",
                        "Sobreposição", "com.example.app", 2, null),
                new ScanFinding(ScanFinding.Level.LOW, "Inicialização automática declarada",
                        "Boot", "com.example.app", 1, null),
                new ScanFinding(ScanFinding.Level.LOW, "Indicador heurístico de acesso remoto",
                        "Heurística", "com.example.app", 1, null)));
        assertEquals(3, actions.size());
        assertEquals(RemediationPlanner.Kind.USAGE_ACCESS, actions.get(0).kind);
        assertEquals(RemediationPlanner.Kind.OVERLAY, actions.get(1).kind);
        assertEquals(RemediationPlanner.Kind.APP_DETAILS, actions.get(2).kind);
    }

    @Test public void prioritizesCriticalFindingBeforeManyLowFindings() {
        List<ScanFinding> findings = new java.util.ArrayList<>();
        for (int i = 0; i < 45; i++) {
            findings.add(new ScanFinding(ScanFinding.Level.LOW, "Versão antiga", "",
                    "com.example.app" + i, 1, null));
        }
        findings.add(new ScanFinding(ScanFinding.Level.CRITICAL,
                "Administrador ativo", "Revise", "com.example.critical", 10, null));
        List<RemediationPlanner.Action> actions = RemediationPlanner.plan(findings);
        assertEquals(40, actions.size());
        assertEquals("com.example.critical", actions.get(0).packageName);
        assertEquals(RemediationPlanner.Kind.SECURITY, actions.get(0).kind);
    }
}
