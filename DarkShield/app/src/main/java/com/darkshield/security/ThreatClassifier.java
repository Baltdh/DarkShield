package com.darkshield.security;

import java.util.List;
import java.util.Locale;

/**
 * Converts technical findings into a user-facing evidence class without
 * claiming that an application is confirmed malware.
 */
public final class ThreatClassifier {
    public enum Category {
        INFORMATIONAL("Informativo"),
        PRIVACY_REVIEW("Privacidade para revisão"),
        CAPABILITY_REVIEW("Capacidades para revisão"),
        SUSPICIOUS_BEHAVIOR("Comportamento suspeito"),
        STRONG_THREAT_INDICATORS("Indicadores fortes de ameaça");

        public final String label;

        Category(String label) {
            this.label = label;
        }
    }

    private ThreatClassifier() {}

    public static Category classify(List<ScanFinding> findings, String packageName) {
        if (findings == null || findings.isEmpty()
                || packageName == null || packageName.trim().isEmpty()) {
            return Category.INFORMATIONAL;
        }

        boolean hasReviewFinding = false;
        boolean privacyOnly = true;
        boolean capability = false;
        boolean suspicious = false;
        boolean strong = false;

        for (ScanFinding finding : findings) {
            if (finding == null || finding.level == null
                    || !packageName.equals(finding.packageName)
                    || finding.level == ScanFinding.Level.INFO) {
                continue;
            }

            hasReviewFinding = true;
            String title = finding.title == null
                    ? "" : finding.title.toLowerCase(Locale.ROOT);
            boolean privacy = isPrivacyFinding(title);
            privacyOnly &= privacy;

            if (title.contains("correlação")) {
                suspicious = true;
                if (finding.level == ScanFinding.Level.HIGH
                        || finding.level == ScanFinding.Level.CRITICAL) {
                    strong = true;
                }
            }

            if (title.contains("carregamento dinâmico")
                    || title.contains("instalação de apk")
                    || title.contains("acesso remoto")
                    || title.contains("administrador")
                    || title.contains("sobreposição")
                    || title.contains("acessibilidade")
                    || title.contains("inicialização automática")
                    || title.contains("instrumentação")) {
                capability = true;
            }

            if (finding.level == ScanFinding.Level.CRITICAL) {
                strong = true;
            } else if (finding.level == ScanFinding.Level.HIGH) {
                suspicious = true;
            } else if (finding.level == ScanFinding.Level.MEDIUM && !privacy) {
                suspicious = true;
            }
        }

        if (strong) return Category.STRONG_THREAT_INDICATORS;
        if (suspicious) return Category.SUSPICIOUS_BEHAVIOR;
        if (hasReviewFinding && privacyOnly) return Category.PRIVACY_REVIEW;
        if (hasReviewFinding && capability) return Category.CAPABILITY_REVIEW;
        return hasReviewFinding ? Category.CAPABILITY_REVIEW : Category.INFORMATIONAL;
    }

    static boolean isPrivacyFinding(String normalizedTitle) {
        if (normalizedTitle == null) return false;
        return normalizedTitle.contains("sms")
                || normalizedTitle.contains("chamadas")
                || normalizedTitle.contains("microfone")
                || normalizedTitle.contains("câmera")
                || normalizedTitle.contains("contatos")
                || normalizedTitle.contains("localização")
                || normalizedTitle.contains("notifica")
                || normalizedTitle.contains("dados de uso")
                || normalizedTitle.contains("estado do telefone");
    }
}
