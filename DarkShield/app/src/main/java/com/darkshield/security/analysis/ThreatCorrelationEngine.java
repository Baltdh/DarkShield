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
        Map<String, Boolean> dynamicCode = new HashMap<>();
        Map<String, Boolean> batteryExempt = new HashMap<>();
        Map<String, Boolean> vpn = new HashMap<>();
        Map<String, Boolean> exposedProvider = new HashMap<>();
        Map<String, Boolean> unknownOrigin = new HashMap<>();
        Map<String, Boolean> identityTamper = new HashMap<>();
        Map<String, Boolean> installerChanged = new HashMap<>();
        Map<String, Boolean> thirdPartyKeyboard = new HashMap<>();
        Map<String, Boolean> location = new HashMap<>();
        Map<String, Boolean> media = new HashMap<>();
        Map<String, Boolean> messaging = new HashMap<>();
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
            if (t.contains("carregamento dinâmico de código")) dynamicCode.put(p, true);
            if (t.contains("exceção de otimização de bateria ativa")) batteryExempt.put(p, true);
            if (t.contains("serviço vpn declarado")) vpn.put(p, true);
            if (t.contains("content provider exportado sem proteção")) exposedProvider.put(p, true);
            if (t.contains("origem de instalação não identificada")) unknownOrigin.put(p, true);
            if (t.contains("assinatura do aplicativo alterada")
                    || t.contains("downgrade de versão detectado")) {
                identityTamper.put(p, true);
            }
            if (t.contains("origem de instalação alterada")) installerChanged.put(p, true);
            if (t.contains("teclado de terceiros ativo")) thirdPartyKeyboard.put(p, true);
            if (t.contains("acesso à localização")) location.put(p, true);
            if (t.contains("microfone/câmera")) media.put(p, true);
            if (t.contains("acesso a sms") || t.contains("histórico de chamadas")) {
                messaging.put(p, true);
            }
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

            if (a && o && !r && !b) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Correlação de acessibilidade e sobreposição",
                        "O mesmo pacote possui serviço de acessibilidade ativo e permissão de sobreposição. Essa combinação pode permitir observar ou interferir com interfaces de outros aplicativos; isoladamente, não prova captura de entrada nem malware.",
                        p, 5,
                        "Confirme a origem do aplicativo e se acessibilidade e sobreposição são realmente necessárias"));
            } else if (a && n && !r && !o && !b) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Correlação de acessibilidade e notificações",
                        "O mesmo pacote possui serviço de acessibilidade ativo e acesso ativo às notificações.",
                        p, 4,
                        "Confirme que o aplicativo é reconhecido e que ambos os acessos são necessários"));
            }
        }

        for (String p : dynamicCode.keySet()) {
            boolean i = apkInstall.getOrDefault(p, false);
            boolean a = accessibility.getOrDefault(p, false);
            boolean o = overlay.getOrDefault(p, false);
            boolean r = remote.getOrDefault(p, false);
            int s = sensitive.getOrDefault(p, 0);

            if (i && (a || o || r)) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.HIGH,
                        "Correlação de carregamento dinâmico e controle privilegiado",
                        "O pacote combina capacidade de carregar código dinamicamente, solicitar instalação de APKs e outro mecanismo de controle privilegiado. Essa cadeia merece revisão aprofundada, mas ainda não prova execução de payload malicioso.",
                        p, 8,
                        "Revise a origem e assinatura do app; remova privilégios desnecessários e considere desinstalar se a combinação não for esperada"));
            } else if (i || (s > 0 && (a || o || r))) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Correlação de carregamento dinâmico com capacidade sensível",
                        "O pacote combina carregamento dinâmico de código com outra capacidade que pode ampliar o impacto de código obtido ou ativado posteriormente.",
                        p, 5,
                        "Confirme se plugins, módulos ou atualizações dinâmicas fazem parte da função legítima do aplicativo"));
            }
        }

        for (String p : thirdPartyKeyboard.keySet()) {
            boolean a = accessibility.getOrDefault(p, false);
            boolean o = overlay.getOrDefault(p, false);
            boolean b = boot.getOrDefault(p, false);

            if (a && o) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.HIGH,
                        "Correlação de teclado, acessibilidade e sobreposição",
                        "O mesmo pacote está ativo como teclado de terceiros e também possui acessibilidade ativa e sobreposição. Essa combinação pode ampliar a capacidade de observar ou interferir com entrada do usuário, mas não prova keylogging.",
                        p, 8,
                        "Confirme se o teclado é reconhecido e se acessibilidade/sobreposição são realmente necessárias"));
            } else if (a || o || b) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Correlação de teclado com capacidade de captura",
                        "O teclado de terceiros também apresenta uma capacidade adicional relacionada a observação, sobreposição ou persistência.",
                        p, 5,
                        "Revise o teclado e remova privilégios adicionais que não façam parte da função esperada"));
            }
        }

        java.util.Set<String> surveillancePackages = new java.util.HashSet<>();
        surveillancePackages.addAll(boot.keySet());
        surveillancePackages.retainAll(sensitive.keySet());
        for (String p : surveillancePackages) {
            int privacySignals = 0;
            if (location.getOrDefault(p, false)) privacySignals++;
            if (media.getOrDefault(p, false)) privacySignals++;
            if (messaging.getOrDefault(p, false)) privacySignals++;
            if (notification.getOrDefault(p, false)) privacySignals++;

            boolean a = accessibility.getOrDefault(p, false);
            if (privacySignals >= 2 && a) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.HIGH,
                        "Correlação de persistência e coleta sensível",
                        "O pacote combina inicialização automática, acessibilidade ativa e múltiplos acessos a dados/sensores sensíveis. Essa combinação é compatível com capacidades observadas em spyware/stalkerware, embora também possa existir em apps legítimos.",
                        p, 8,
                        "Confirme a finalidade do aplicativo, sua origem e se todos esses acessos foram concedidos conscientemente"));
            } else if (privacySignals >= 2) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Correlação de persistência e coleta sensível",
                        "O pacote combina inicialização automática com múltiplos acessos a dados/sensores sensíveis. Isso merece revisão de privacidade e persistência.",
                        p, 5,
                        "Revise permissões, inicialização automática e a necessidade real desses acessos"));
            }
        }

        for (String p : identityTamper.keySet()) {
            boolean d = dynamicCode.getOrDefault(p, false);
            boolean i = apkInstall.getOrDefault(p, false);
            boolean a = accessibility.getOrDefault(p, false);
            boolean o = overlay.getOrDefault(p, false);
            boolean r = remote.getOrDefault(p, false);
            boolean m = admin.getOrDefault(p, false);

            if (d || i || a || o || r || m) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.HIGH,
                        "Correlação de integridade do pacote e capacidade privilegiada",
                        "O pacote apresenta mudança relevante de identidade/versão junto de uma capacidade que pode ampliar impacto ou persistência. A combinação merece revisão prioritária; ela ainda não identifica sozinha a causa da mudança.",
                        p, 9,
                        "Confirme a origem e assinatura; remova privilégios desnecessários e reinstale pela fonte oficial se a mudança não for esperada"));
            }
        }

        for (String p : installerChanged.keySet()) {
            boolean d = dynamicCode.getOrDefault(p, false);
            boolean i = apkInstall.getOrDefault(p, false);
            boolean r = remote.getOrDefault(p, false);
            if (d || i || r) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Correlação de mudança de origem e capacidade de distribuição",
                        "O instalador conhecido mudou desde a referência anterior e o pacote também apresenta capacidade de carregar código, instalar APKs ou acesso remoto heurístico.",
                        p, 5,
                        "Confirme se a mudança de origem foi intencional e compare a assinatura com a distribuição oficial"));
            }
        }

        for (String p : batteryExempt.keySet()) {
            boolean b = boot.getOrDefault(p, false);
            boolean a = accessibility.getOrDefault(p, false);
            boolean n = notification.getOrDefault(p, false);
            boolean r = remote.getOrDefault(p, false);
            if (b && (a || n || r)) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.HIGH,
                        "Correlação de persistência prolongada",
                        "O pacote combina inicialização após o boot, exceção ativa de otimização de bateria e uma capacidade privilegiada adicional. Essa combinação pode manter o aplicativo ativo por longos períodos, mas também existe em aplicativos legítimos.",
                        p, 7,
                        "Confirme se a execução persistente é esperada e remova acessos que não sejam necessários"));
            } else if (b) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Correlação de persistência após reinicialização",
                        "O pacote declara inicialização após o boot e está fora das otimizações de bateria. A combinação favorece execução persistente, mas não prova comportamento malicioso.",
                        p, 4,
                        "Confirme se o aplicativo realmente precisa iniciar e permanecer ativo em segundo plano"));
            }
        }

        for (String p : exposedProvider.keySet()) {
            if (sensitive.getOrDefault(p, 0) > 0
                    && (accessibility.getOrDefault(p, false)
                        || remote.getOrDefault(p, false))) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Correlação de superfície exposta e acesso sensível",
                        "O pacote combina um Content Provider exportado sem proteção explícita com acesso sensível e outra capacidade de controle. Isso amplia a superfície de exposição e merece revisão.",
                        p, 5,
                        "Revise a origem do aplicativo, seus privilégios e a necessidade de componentes públicos"));
            }
        }

        for (String p : vpn.keySet()) {
            if (accessibility.getOrDefault(p, false)
                    || notification.getOrDefault(p, false)
                    || remote.getOrDefault(p, false)) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Correlação de VPN e acesso privilegiado",
                        "O pacote declara serviço VPN e também possui uma capacidade privilegiada adicional. VPNs legítimas são comuns; a combinação merece revisão apenas quando o aplicativo não é reconhecido ou esses acessos não são esperados.",
                        p, 4,
                        "Confirme se você reconhece o aplicativo e se VPN e demais acessos fazem parte da função esperada"));
            }
        }

        for (String p : unknownOrigin.keySet()) {
            if (dynamicCode.getOrDefault(p, false)
                    && (apkInstall.getOrDefault(p, false)
                        || accessibility.getOrDefault(p, false)
                        || remote.getOrDefault(p, false))) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Correlação de origem desconhecida e código dinâmico",
                        "O Android não informou um instalador conhecido e o pacote também apresenta carregamento dinâmico combinado com outra capacidade relevante. Origem desconhecida isoladamente não é tratada como ameaça.",
                        p, 5,
                        "Confirme a procedência e assinatura do APK antes de manter privilégios sensíveis ativos"));
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

            if (accessibility.getOrDefault(p, false)) {
                derived.add(new ScanFinding(
                        ScanFinding.Level.HIGH,
                        "Correlação de administrador e acessibilidade",
                        "O mesmo pacote possui administrador do dispositivo e serviço de acessibilidade ativos/declarados.",
                        p, 7,
                        "Confirme que ambas as capacidades foram autorizadas conscientemente"));
            }
        }

        // Add threat-intelligence context after correlation has identified a
        // meaningful combination. The context is explanatory and does not alter score.
        for (int i = 0; i < derived.size(); i++) {
            ScanFinding finding = derived.get(i);
            String annotation = ThreatKnowledgeBase.annotate(finding.title);
            if (annotation == null || annotation.trim().isEmpty()) continue;
            String detail = finding.detail == null ? "" : finding.detail;
            if (!detail.contains(annotation)) {
                detail = detail + " " + annotation;
                derived.set(i, new ScanFinding(
                        finding.level,
                        finding.title,
                        detail,
                        finding.packageName,
                        finding.points,
                        finding.action));
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
