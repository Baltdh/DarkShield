package com.darkshield.security.analysis;

import com.darkshield.security.ScanFinding;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class EvidenceGraph {
    public enum Kind {
        ACTIVE_ACCESS,
        PERSISTENCE,
        REMOTE_CONTROL,
        SENSITIVE_DATA,
        INSTALL_TRUST,
        STATIC_ANALYSIS,
        VULNERABILITY,
        CORRELATION,
        ANALYSIS_GAP,
        OTHER
    }

    public static final class Node {
        public final String packageName;
        private final List<ScanFinding> evidence;
        private final Set<Kind> kinds;

        private Node(String packageName, List<ScanFinding> evidence, Set<Kind> kinds) {
            this.packageName = packageName;
            this.evidence = Collections.unmodifiableList(new ArrayList<>(evidence));
            this.kinds = kinds.isEmpty()
                    ? Collections.emptySet()
                    : Collections.unmodifiableSet(EnumSet.copyOf(kinds));
        }

        public List<ScanFinding> evidence() {
            return evidence;
        }

        public Set<Kind> kinds() {
            return kinds;
        }

        public boolean has(Kind kind) {
            return kind != null && kinds.contains(kind);
        }

        public int evidenceCount() {
            return evidence.size();
        }

        public int positivePoints() {
            long total = 0L;
            for (ScanFinding finding : evidence) {
                if (finding != null) total += Math.max(0, finding.points);
            }
            return (int) Math.min(Integer.MAX_VALUE, total);
        }

        public ScanFinding.Level strongestLevel() {
            ScanFinding.Level strongest = ScanFinding.Level.INFO;
            for (ScanFinding finding : evidence) {
                if (finding != null && finding.level != null
                        && finding.level.ordinal() > strongest.ordinal()) {
                    strongest = finding.level;
                }
            }
            return strongest;
        }

        public int securityKindCount() {
            int count = 0;
            for (Kind kind : kinds) {
                if (kind != Kind.OTHER && kind != Kind.ANALYSIS_GAP) count++;
            }
            return count;
        }
    }

    private static final class MutableNode {
        final String packageName;
        final List<ScanFinding> evidence = new ArrayList<>();
        final EnumSet<Kind> kinds = EnumSet.noneOf(Kind.class);

        MutableNode(String packageName) {
            this.packageName = packageName;
        }

        Node freeze() {
            return new Node(packageName, evidence, kinds);
        }
    }

    private final List<Node> packageNodes;
    private final List<ScanFinding> globalEvidence;

    private EvidenceGraph(List<Node> packageNodes, List<ScanFinding> globalEvidence) {
        this.packageNodes = Collections.unmodifiableList(new ArrayList<>(packageNodes));
        this.globalEvidence = Collections.unmodifiableList(new ArrayList<>(globalEvidence));
    }

    public static EvidenceGraph from(List<ScanFinding> findings) {
        if (findings == null || findings.isEmpty()) {
            return new EvidenceGraph(Collections.emptyList(), Collections.emptyList());
        }

        Map<String, MutableNode> byPackage = new HashMap<>();
        List<ScanFinding> global = new ArrayList<>();

        for (ScanFinding finding : findings) {
            if (finding == null) continue;
            if (finding.packageName == null || finding.packageName.trim().isEmpty()) {
                global.add(finding);
                continue;
            }

            MutableNode node = byPackage.get(finding.packageName);
            if (node == null) {
                node = new MutableNode(finding.packageName);
                byPackage.put(finding.packageName, node);
            }
            node.evidence.add(finding);
            node.kinds.addAll(classify(finding));
        }

        List<Node> nodes = new ArrayList<>();
        for (MutableNode node : byPackage.values()) nodes.add(node.freeze());
        nodes.sort((left, right) -> {
            int order = left.packageName.compareToIgnoreCase(right.packageName);
            return order != 0 ? order : left.packageName.compareTo(right.packageName);
        });

        return new EvidenceGraph(nodes, global);
    }

    public List<Node> packageNodes() {
        return packageNodes;
    }

    public List<ScanFinding> globalEvidence() {
        return globalEvidence;
    }

    static Set<Kind> classify(ScanFinding finding) {
        EnumSet<Kind> structured = structuredKinds(finding);
        if (!structured.isEmpty()) return structured;
        return classifyLegacyText(finding);
    }

    private static EnumSet<Kind> structuredKinds(ScanFinding finding) {
        EnumSet<Kind> result = EnumSet.noneOf(Kind.class);
        if (finding == null || finding.evidenceTags == null || finding.evidenceTags.isEmpty()) {
            return result;
        }

        for (ScanFinding.EvidenceTag tag : finding.evidenceTags) {
            if (tag == null) continue;
            switch (tag) {
                case ACTIVE_ACCESS:
                    result.add(Kind.ACTIVE_ACCESS);
                    break;
                case PERSISTENCE:
                    result.add(Kind.PERSISTENCE);
                    break;
                case REMOTE_CONTROL:
                    result.add(Kind.REMOTE_CONTROL);
                    break;
                case SENSITIVE_DATA:
                    result.add(Kind.SENSITIVE_DATA);
                    break;
                case INSTALL_TRUST:
                    result.add(Kind.INSTALL_TRUST);
                    break;
                case STATIC_ANALYSIS:
                    result.add(Kind.STATIC_ANALYSIS);
                    break;
                case VULNERABILITY:
                    result.add(Kind.VULNERABILITY);
                    break;
                case CORRELATION:
                    result.add(Kind.CORRELATION);
                    break;
                case ANALYSIS_GAP:
                    result.add(Kind.ANALYSIS_GAP);
                    break;
                default:
                    break;
            }
        }
        return result;
    }

    private static Set<Kind> classifyLegacyText(ScanFinding finding) {
        EnumSet<Kind> result = EnumSet.noneOf(Kind.class);
        if (finding == null) return result;

        String title = finding.title == null ? "" : finding.title.toLowerCase(Locale.ROOT);
        String detail = finding.detail == null ? "" : finding.detail.toLowerCase(Locale.ROOT);
        String combined = title + " " + detail;

        if (title.contains("correlação")) result.add(Kind.CORRELATION);

        if (title.contains("ativo")
                || title.contains("ativa")
                || title.contains("concedida")
                || title.contains("acesso especial")
                || title.contains("administrador do dispositivo")
                || title.contains("depuração usb")
                || title.contains("binário de root")) {
            result.add(Kind.ACTIVE_ACCESS);
        }

        if (combined.contains("inicialização automática")
                || combined.contains("boot")
                || combined.contains("otimização de bateria")
                || combined.contains("persist")) {
            result.add(Kind.PERSISTENCE);
        }

        if (combined.contains("acesso remoto")
                || combined.contains("captura de tela")
                || combined.contains("mediaprojection")
                || combined.contains("controle remoto")
                || combined.contains("remote")) {
            result.add(Kind.REMOTE_CONTROL);
        }

        if (combined.contains("sms")
                || combined.contains("notifica")
                || combined.contains("histórico de chamadas")
                || combined.contains("microfone")
                || combined.contains("câmera")
                || combined.contains("contatos")
                || combined.contains("localização")
                || combined.contains("dados de uso")
                || combined.contains("teclado")) {
            result.add(Kind.SENSITIVE_DATA);
        }

        if (combined.contains("origem de instalação")
                || combined.contains("instalador")
                || combined.contains("assinatura")
                || combined.contains("certificado")
                || combined.contains("target sdk")
                || combined.contains("testonly")
                || combined.contains("debuggable")
                || combined.contains("instalação de apk")) {
            result.add(Kind.INSTALL_TRUST);
        }

        if (combined.contains("código dinâmico")
                || combined.contains("dex")
                || combined.contains("biblioteca")
                || combined.contains("webview")
                || combined.contains("execução de comandos")
                || combined.contains("instrumentação")
                || combined.contains("estrutura zip do apk")
                || combined.contains("sha-256 do apk")) {
            result.add(Kind.STATIC_ANALYSIS);
        }

        if (combined.contains("provider exportado")
                || combined.contains("componentes exportados")
                || combined.contains("tráfego sem criptografia")
                || combined.contains("patch de segurança")
                || combined.contains("vulnerab")
                || combined.contains("target sdk antigo")) {
            result.add(Kind.VULNERABILITY);
        }

        if (combined.contains("falha")
                || combined.contains("incompleto")
                || combined.contains("indisponível")
                || combined.contains("não foi possível")
                || combined.contains("análise foi limitada")
                || combined.contains("sem análise completa")) {
            result.add(Kind.ANALYSIS_GAP);
        }

        if (result.isEmpty()) result.add(Kind.OTHER);
        return result;
    }

}