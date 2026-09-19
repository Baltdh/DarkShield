package com.darkshield.security;

import com.darkshield.security.analysis.ThreatKnowledgeBase;
import org.junit.Test;
import static org.junit.Assert.*;

public class ThreatKnowledgeBaseTest {
    @Test public void remoteCorrelationGetsAttackContext() {
        String result = ThreatKnowledgeBase.annotate("Correlação de acesso remoto");
        assertNotNull(result);
        assertTrue(result.contains("T1663"));
    }

    @Test public void accessibilityGetsAttackContext() {
        String result = ThreatKnowledgeBase.annotate("Correlação de administrador e acessibilidade");
        assertNotNull(result);
        assertTrue(result.contains("T1453"));
    }

    @Test public void genericTitleDoesNotInventThreatContext() {
        assertNull(ThreatKnowledgeBase.annotate("Aplicativo atualizado"));
    }
}
