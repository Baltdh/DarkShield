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
        assertTrue(actions.get(0).uninstallCandidate);
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
}
