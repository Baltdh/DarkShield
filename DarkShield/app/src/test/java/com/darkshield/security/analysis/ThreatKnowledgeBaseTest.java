package com.darkshield.security.analysis;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class ThreatKnowledgeBaseTest {

    @Test public void remoteAccessAnnotationIncludesTechniqueAndCaveat() {
        String annotation = ThreatKnowledgeBase.annotate(
                "Correlação de acesso remoto e administrador");

        assertNotNull(annotation);
        assertTrue(annotation.contains("T1663"));
        assertTrue(annotation.contains("não prova"));
    }

    @Test public void accessibilityAnnotationIsCaseInsensitive() {
        String annotation = ThreatKnowledgeBase.annotate(
                "CORRELAÇÃO DE ACESSIBILIDADE");

        assertNotNull(annotation);
        assertTrue(annotation.contains("T1453"));
    }

    @Test public void notificationAnnotationCoversSensitiveNotificationAccess() {
        String annotation = ThreatKnowledgeBase.annotate(
                "Acesso a notificações ativo");

        assertNotNull(annotation);
        assertTrue(annotation.contains("T1517"));
    }

    @Test public void administratorAnnotationCoversDeviceAdmin() {
        String annotation = ThreatKnowledgeBase.annotate(
                "Administrador do dispositivo ativo");

        assertNotNull(annotation);
        assertTrue(annotation.contains("T1626.001"));
    }

    @Test public void overlayAnnotationKeepsSingleSignalCaveat() {
        String annotation = ThreatKnowledgeBase.annotate(
                "Permissão de sobreposição concedida");

        assertNotNull(annotation);
        assertTrue(annotation.contains("T1417.002"));
        assertTrue(annotation.contains("não prova"));
    }

    @Test public void smsAnnotationCoversSmsControl() {
        String annotation = ThreatKnowledgeBase.annotate("Acesso a SMS");

        assertNotNull(annotation);
        assertTrue(annotation.contains("T1582"));
    }

    @Test public void apkInstallAnnotationCoversRuntimeCodeContext() {
        String annotation = ThreatKnowledgeBase.annotate(
                "Pode solicitar instalação de APKs");

        assertNotNull(annotation);
        assertTrue(annotation.contains("T1407"));
        assertTrue(annotation.contains("não prova"));
    }

    @Test public void unrelatedFindingHasNoAnnotation() {
        assertNull(ThreatKnowledgeBase.annotate("Origem de instalação"));
        assertNull(ThreatKnowledgeBase.annotate(null));
    }

    @Test public void knownFamilyContextIsExplicitlyNonVerdict() {
        String context = ThreatKnowledgeBase.knownFamilyContext();

        assertNotNull(context);
        assertFalse(context.trim().isEmpty());
        assertTrue(context.contains("não é tratada como confirmação"));
    }
}
