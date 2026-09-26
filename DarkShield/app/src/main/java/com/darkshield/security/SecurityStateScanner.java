package com.darkshield.security;

import android.content.Context;
import android.os.Build;

import androidx.security.state.SecurityPatchState;

import java.util.ArrayList;
import java.util.List;

public final class SecurityStateScanner {
    private SecurityStateScanner() {}

    public static List<ScanFinding> scan(Context context) {
        List<ScanFinding> findings = new ArrayList<>();
        if (context == null) return findings;

        final SecurityPatchState state;
        try {
            state = new SecurityPatchState(context.getApplicationContext());
        } catch (RuntimeException e) {
            findings.add(unavailable(
                    "Estado de segurança por componente",
                    "Não foi possível inicializar a biblioteca AndroidX Security State"));
            return findings;
        }

        addComponent(
                findings,
                state,
                SecurityPatchState.COMPONENT_SYSTEM,
                "Estado de patch — sistema",
                "Nível de patch do Android System informado localmente pelo dispositivo");

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            addComponent(
                    findings,
                    state,
                    SecurityPatchState.COMPONENT_SYSTEM_MODULES,
                    "Estado de patch — módulos Mainline",
                    "Nível de patch dos módulos atualizáveis do sistema informado localmente");
        } else {
            findings.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "Estado de patch — módulos Mainline",
                    "Não se aplica a esta versão do Android; Project Mainline é suportado a partir do Android 10",
                    null, 0, null));
        }

        addComponent(
                findings,
                state,
                SecurityPatchState.COMPONENT_KERNEL,
                "Estado de patch — kernel",
                "Versão de segurança do kernel observada localmente");

        VulnerabilityReportCache.Snapshot cachedReport =
                VulnerabilityReportCache.load(context.getApplicationContext());
        if (cachedReport == null) {
            findings.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "Base OSV local",
                    "Nenhum relatório de vulnerabilidades OSV validado está armazenado. "
                            + "A leitura por componente continua disponível, mas conformidade com CVEs não é avaliada.",
                    null, 0, null));
        } else {
            try {
                state.loadVulnerabilityReport(cachedReport.json);
                boolean fullyUpdated = state.isDeviceFullyUpdated();
                long ageDays = Math.max(
                        0L,
                        (System.currentTimeMillis() - cachedReport.savedAtMillis)
                                / (24L * 60L * 60L * 1000L));
                findings.add(new ScanFinding(
                        ScanFinding.Level.INFO,
                        "Conformidade com relatório OSV em cache",
                        (fullyUpdated
                                ? "Os componentes consultáveis estão alinhados aos níveis publicados no relatório OSV armazenado"
                                : "Um ou mais componentes consultáveis não estão alinhados aos níveis publicados no relatório OSV armazenado")
                                + ". Cache salvo há aproximadamente " + ageDays + " dia(s)"
                                + (cachedReport.isStale(System.currentTimeMillis())
                                        ? " e marcado como desatualizado para renovação."
                                        : "."),
                        null, 0,
                        fullyUpdated
                                ? null
                                : "Procure atualizações do sistema e atualize a base OSV antes de concluir que há exposição a uma CVE específica"));
            } catch (IllegalArgumentException | IllegalStateException e) {
                findings.add(unavailable(
                        "Conformidade com relatório OSV em cache",
                        "O relatório armazenado não pôde ser aplicado à avaliação atual"));
            }
        }

        findings.add(new ScanFinding(
                ScanFinding.Level.INFO,
                "Cobertura do estado de segurança",
                cachedReport == null
                        ? "A leitura por componente é local. CVEs publicadas não são avaliadas sem um relatório OSV validado."
                        : "A leitura por componente é local; a comparação de atualização usa o relatório OSV validado em cache. "
                                + "Esse resultado mede estado de patch e não prova exploração ou comprometimento.",
                null, 0, null));

        return findings;
    }

    private static void addComponent(
            List<ScanFinding> out,
            SecurityPatchState state,
            String component,
            String title,
            String prefix) {
        try {
            SecurityPatchState.SecurityPatchLevel level =
                    state.getDeviceSecurityPatchLevel(component);
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    title,
                    prefix + ": " + level.toString(),
                    null, 0, null));
        } catch (IllegalStateException | IllegalArgumentException e) {
            out.add(unavailable(title, "O Android não forneceu um nível de patch utilizável"));
        } catch (RuntimeException e) {
            out.add(unavailable(title, "A consulta local do componente falhou"));
        }
    }

    static ScanFinding unavailable(String title, String detail) {
        return new ScanFinding(
                ScanFinding.Level.INFO,
                title,
                detail + ". A ausência desse dado não deve ser interpretada como falha de segurança confirmada.",
                null, 0, null);
    }
}
