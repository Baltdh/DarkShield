package com.darkshield.security.analysis;

import java.util.Locale;

/**
 * Curated offline threat knowledge derived from public Android threat research.
 * It maps already-observed capabilities to ATT&CK Mobile techniques.
 *
 * This class deliberately does not declare a package malicious from one signal.
 * Exact malware/hash verdicts require a trusted, licensed threat-intelligence feed.
 */
public final class ThreatKnowledgeBase {
    private ThreatKnowledgeBase() {}

    public static String annotate(String title) {
        if (title == null) return null;
        String t = title.toLowerCase(Locale.ROOT);

        if (t.contains("teclado") && (t.contains("acessibilidade") || t.contains("captura"))) {
            return "MITRE ATT&CK Mobile T1417/T1417.001 (Input Capture/Keylogging): teclado de terceiros, acessibilidade e sobreposição são capacidades que podem ser abusadas para observar entrada. A correlação indica risco de captura, não confirmação de keylogging.";
        }
        if (t.contains("persistência") && t.contains("coleta sensível")) {
            return "MITRE ATT&CK Mobile: persistência após boot combinada com acesso a localização, áudio/vídeo, mensagens ou notificações aumenta a prioridade de revisão para spyware/stalkerware. A combinação ainda pode existir em aplicativos legítimos.";
        }
        if (t.contains("carregamento dinâmico")) {
            return "MITRE ATT&CK Mobile T1407 (Download New Code at Runtime): ameaças podem buscar ou ativar código após a instalação para escapar de análise estática. Referências a APIs de carregamento dinâmico também aparecem em apps legítimos, portanto esse sinal precisa ser correlacionado com origem, instalação de APKs e privilégios.";
        }
        if (t.contains("acessibilidade") && t.contains("sobreposição")) {
            return "MITRE ATT&CK Mobile T1453 (Abuse Accessibility Features) e T1417.002 (GUI Input Capture): a combinação de acessibilidade e sobreposição pode ser abusada para observar ou imitar interfaces; a presença das capacidades não confirma captura de credenciais.";
        }
        if (t.contains("controle remoto") || t.contains("acesso remoto")) {
            return "MITRE ATT&CK Mobile T1663 (Remote Access Software): acesso remoto legítimo também existe; esse sinal isolado não prova abuso, e a correlação com outras capacidades é o que aumenta a prioridade.";
        }
        if (t.contains("acessibilidade")) {
            return "MITRE ATT&CK Mobile T1453 (Abuse Accessibility Features): ameaças Android conhecidas podem abusar da acessibilidade para interação e captura de dados.";
        }
        if (t.contains("notifica")) {
            return "MITRE ATT&CK Mobile T1517 (Access Notifications): notificações podem conter códigos e dados sensíveis.";
        }
        if (t.contains("administrador")) {
            return "MITRE ATT&CK Mobile T1626.001 (Device Administrator Permissions): esse privilégio pode aumentar o controle sobre o dispositivo.";
        }
        if (t.contains("sobreposição")) {
            return "MITRE ATT&CK Mobile T1417.002 (GUI Input Capture) é relevante quando sobreposições são usadas para capturar credenciais; a permissão isolada não prova isso.";
        }
        if (t.contains("sms")) {
            return "MITRE ATT&CK Mobile T1582 (SMS Control) é uma capacidade observada em malware Android, mas apps legítimos também podem precisar de SMS.";
        }
        if (t.contains("instalação de apk")) {
            return "MITRE ATT&CK Mobile T1407 (Download New Code at Runtime) aparece em famílias Android que baixam código/APKs adicionais; a capacidade de instalar sozinha não prova esse comportamento.";
        }
        if (t.contains("software discovery") || t.contains("aplicativos analisados")) {
            return "MITRE ATT&CK Mobile T1418 (Software Discovery) descreve a descoberta de aplicativos instalados; o DarkShield usa essa informação defensivamente para auditar o aparelho.";
        }
        return null;
    }

    public static String knownFamilyContext() {
        return "A base de conhecimento considera famílias Android documentadas publicamente, como BRATA, Cerberus, Anubis e Chameleon. A presença de um nome de família no APK não é tratada como confirmação; veredictos exatos serão feitos por hash/assinatura quando uma fonte confiável estiver disponível.";
    }
}
