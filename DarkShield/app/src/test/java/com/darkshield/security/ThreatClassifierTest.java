package com.darkshield.security;

import java.util.Arrays;
import java.util.Collections;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class ThreatClassifierTest {
    private static ScanFinding finding(
            ScanFinding.Level level, String title, int points) {
        return new ScanFinding(
                level, title, "detail", "com.example.target", points, "action");
    }

    @Test public void infoOnlyIsInformational() {
        assertEquals(
                ThreatClassifier.Category.INFORMATIONAL,
                ThreatClassifier.classify(
                        Collections.singletonList(
                                finding(ScanFinding.Level.INFO, "Origem de instalação", 0)),
                        "com.example.target"));
    }

    @Test public void privacyOnlyStaysPrivacyReview() {
        assertEquals(
                ThreatClassifier.Category.PRIVACY_REVIEW,
                ThreatClassifier.classify(Arrays.asList(
                        finding(ScanFinding.Level.LOW, "Acesso a contatos", 1),
                        finding(ScanFinding.Level.LOW, "Acesso à localização", 1)),
                        "com.example.target"));
    }

    @Test public void lowDynamicLoadingIsCapabilityReview() {
        assertEquals(
                ThreatClassifier.Category.CAPABILITY_REVIEW,
                ThreatClassifier.classify(
                        Collections.singletonList(
                                finding(ScanFinding.Level.LOW,
                                        "Capacidade de carregamento dinâmico de código", 2)),
                        "com.example.target"));
    }

    @Test public void mediumCorrelationIsSuspiciousBehavior() {
        assertEquals(
                ThreatClassifier.Category.SUSPICIOUS_BEHAVIOR,
                ThreatClassifier.classify(
                        Collections.singletonList(
                                finding(ScanFinding.Level.MEDIUM,
                                        "Correlação de acessibilidade e sobreposição", 5)),
                        "com.example.target"));
    }

    @Test public void highCorrelationIsStrongThreatIndicatorNotConfirmedMalware() {
        assertEquals(
                ThreatClassifier.Category.STRONG_THREAT_INDICATORS,
                ThreatClassifier.classify(
                        Collections.singletonList(
                                finding(ScanFinding.Level.HIGH,
                                        "Correlação de carregamento dinâmico e controle privilegiado", 8)),
                        "com.example.target"));
    }

    @Test public void findingsFromOtherPackagesAreIgnored() {
        assertEquals(
                ThreatClassifier.Category.INFORMATIONAL,
                ThreatClassifier.classify(
                        Collections.singletonList(
                                new ScanFinding(
                                        ScanFinding.Level.HIGH,
                                        "Correlação de acesso remoto",
                                        "detail",
                                        "com.example.other",
                                        8,
                                        "action")),
                        "com.example.target"));
    }
}
