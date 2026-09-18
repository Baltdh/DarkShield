package com.darkshield.security.analysis;

import com.darkshield.security.ScanFinding;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class ThreatCorrelationEngine {
    private ThreatCorrelationEngine() {}

    private static int compareDeterministically(String left, String right) {
        String leftValue = left == null ? "" : left;
        String rightValue = right == null ? "" : right;
        int order = leftValue.compareToIgnoreCase(rightValue);
        return order != 0 ? order : leftValue.compareTo(rightValue);
    }

    private static int compareCorrelationStrength(ScanFinding left, ScanFinding right) {
        int severity = Integer.compare(right.level.ordinal(), left.level.ordinal());
        if (severity != 0) return severity;
        int points = Integer.compare(Math.max(0, right.points), Math.max(0, left.points));
        if (points != 0) return points;
        int title = compareDeterministically(left.title, right.title);
        if (title != 0) return title;
        int detail = compareDeterministically(left.detail, right.detail);
        if (detail != 0) return detail;
        return compareDeterministically(left.action, right.action);
    }

    public static List<ScanFinding> correlate(List<ScanFinding> findings) {
        List<ScanFinding> derived = new ArrayList<>();
        if (findings == null || findings.isEmpty()) return derived;

        Map<String, Boolean> remote = new HashMap<>();
        Map<String, Boolean> accessibility = new HashMap<>();
        Map<String, Boolean> accessibilityDeclared = new HashMap<>();
        Map<String, Boolean> overlay = new HashMap<>();
        Map<String, Boolean> admin = new HashMap<>();
        Map<String, Boolean> notification = new HashMap<>();
        Map<String, Boolean> boot = new HashMap<>();
        Map<String, Boolean> apkInstall = new HashMap<>();
        Map<String, Integer> sensitive = new HashMap<>();

        for (ScanFinding f : findings) {
            if (f == null || f.packageName == null) continue;
            String p = f.packageName;
            String t = f.title == null ? "" : f.title.toLowerCase(java.util.Locale.ROOT);

            if (t.contains("acesso remoto")) remote.put(p, true);
            if (t.contains("serviço de acessibilidade ativo")) accessibility.put(p, true);
            if (t.contains("serviço de acessibilidade declarado")) accessibilityDeclared.put(p, true);
            if (t.contains("sobreposição")) overlay.put(p, true);
            if (t.contains("administrador do dispositivo")) admin.put(p, true);
            if (t.contains("acesso a notificações ativo")) notification.put(p, true);
            if (t.contains("inicialização automática declarada")) boot.put(p, true);
            if (t.contains("pode solicitar instalação de apks")) apkInstall.put(p, true);
            if (t.contains("acesso a sms")
                    || t.contains("histórico de chamadas")
                    || t.contains("microfone/câmera")
                    || t.contains("acesso a contatos")
                    || t.contains("acesso à localização")
                    || t.contains("estado do telefone")
                    || t.contains("dados de uso")) {
                sensitive.put(p, sensitive.getOrDefault(p, 0) + 1);
            }
        }

        for (String p : remote.keySet()) {
            boolean a = accessibility.getOrDefault(p, false);
            boolean declared = accessibilityDeclared.getOrDefault(p, false);
            boolean o = overlay.getOrDefault(p, false);
            boolean n = notification.getOrDefault(p, false);
            boolean b = boot.getOrDefault(p, false);
            boolean i = apkInstall.getOrDefault(p, false);
            int s = sensitive.getOrDefault(p, 0);

            if (a && o) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.HIGH,
                        "Correlação de controle remoto e acesso à interface",
                        "O mesmo pacote apresenta indicadores de acesso remoto, acessibilidade e sobreposição. A combinação merece revisão; isso não constitui prova automática de malware.",
                        p, 7,
                        "Verifique origem, serviço de acessibilidade, sobreposição e finalidade do aplicativo"));
            } else if (a || o || (declared && o)) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Correlação de indicador de acesso remoto",
                        "O mesmo pacote apresenta indicador de acesso remoto combinado com um mecanismo adicional de interação privilegiada.",
                        p, 4,
                        "Confirme se o aplicativo é reconhecido e se esses acessos são esperados"));
            } else if (n) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Acesso remoto combinado com notificações",
                        "O mesmo pacote apresenta indicador de acesso remoto e acesso ativo às notificações.",
                        p, 4,
                        "Confirme se o aplicativo é reconhecido e se a leitura de notificações é necessária"));
            } else if (b) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Acesso remoto combinado com inicialização automática",
                        "O mesmo pacote apresenta indicador de acesso remoto e declara inicialização automática após o boot.",
                        p, 4,
                        "Confirme se o aplicativo é reconhecido e se iniciar com o sistema é realmente necessário"));
            } else if (i) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Acesso remoto combinado com instalação de APK",
                        "O mesmo pacote apresenta indicador de acesso remoto e capacidade operacional para solicitar instalação de APKs.",
                        p, 4,
                        "Confirme se o aplicativo é reconhecido e se a instalação de APKs faz parte da função esperada"));
            } else if (s > 0) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Acesso remoto combinado com dado sensível",
                        "O mesmo pacote apresenta indicador de acesso remoto e pelo menos uma capacidade sensível.",
                        p, 4,
                        "Revise a finalidade e as permissões concedidas ao aplicativo"));
            }
        }

        for (String p : accessibility.keySet()) {
            boolean a = accessibility.getOrDefault(p, false);
            boolean o = overlay.getOrDefault(p, false);
            boolean b = boot.getOrDefault(p, false);
            boolean n = notification.getOrDefault(p, false);
            boolean r = remote.getOrDefault(p, false);

            if (a && n && b && !r && !o) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.HIGH,
                        "Correlação de acessibilidade, notificações e boot",
                        "O mesmo pacote mantém serviço de acessibilidade ativo, acesso ativo às notificações e inicialização automática. Essa combinação merece revisão mesmo sem um marcador nominal de acesso remoto.",
                        p, 7,
                        "Confirme a origem do aplicativo e verifique se as três capacidades são realmente necessárias"));
            } else if (a && o && b && !r) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.HIGH,
                        "Correlação de acessibilidade, sobreposição e boot",
                        "O mesmo pacote declara/expõe um serviço de acessibilidade, acesso de sobreposição e inicialização automática. Essa combinação merece revisão mesmo sem um marcador nominal de acesso remoto.",
                        p, 7,
                        "Confirme a origem do aplicativo e verifique se as três capacidades são realmente necessárias"));
            }

            if (a && n && !r && !o && !b) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Correlação de acessibilidade e notificações",
                        "O mesmo pacote possui serviço de acessibilidade ativo e acesso ativo às notificações.",
                        p, 4,
                        "Confirme que o aplicativo é reconhecido e que ambos os acessos são necessários"));
            }
        }

        for (String p : admin.keySet()) {
            if (remote.getOrDefault(p, false)) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.HIGH,
                        "Correlação de acesso remoto e administrador",
                        "O mesmo pacote apresenta indicador de acesso remoto e administrador do dispositivo ativo. A combinação merece revisão porque reúne controle remoto heurístico com uma capacidade de gerenciamento privilegiada; isso não constitui prova automática de malware.",
                        p, 7,
                        "Confirme a origem do aplicativo e se o administrador do dispositivo foi autorizado conscientemente"));
            }
        }

            if (accessibility.getOrDefault(p, false)) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.HIGH,
                        "Correlação de administrador e acessibilidade",
                        "O mesmo pacote possui administrador do dispositivo e serviço de acessibilidade ativos/declarados.",
                        p, 7,
                        "Confirme que ambas as capacidades foram autorizadas conscientemente"));
            }
        }

        // Multiple independent rules can describe the same package. Keep only the
        // strongest derived correlation so the heuristic score is not inflated by
        // overlapping explanations of the same underlying signal set.
        Map<String, ScanFinding> strongestByPackage = new HashMap<>();
        for (ScanFinding candidate : derived) {
            ScanFinding current = strongestByPackage.get(candidate.packageName);
            if (current == null || compareCorrelationStrength(candidate, current) < 0) {
                strongestByPackage.put(candidate.packageName, candidate);
            }
        }
        derived = new ArrayList<>(strongestByPackage.values());

        derived.sort((left, right) -> {
            int severity = Integer.compare(right.level.ordinal(), left.level.ordinal());
            if (severity != 0) return severity;

            int points = Integer.compare(Math.max(0, right.points), Math.max(0, left.points));
            if (points != 0) return points;

            int packageOrder = compareDeterministically(left.packageName, right.packageName);
            if (packageOrder != 0) return packageOrder;

            int titleOrder = compareDeterministically(left.title, right.title);
            if (titleOrder != 0) return titleOrder;

            int detailOrder = compareDeterministically(left.detail, right.detail);
            if (detailOrder != 0) return detailOrder;

            return compareDeterministically(left.action, right.action);
        });

        return derived;
    }
}
