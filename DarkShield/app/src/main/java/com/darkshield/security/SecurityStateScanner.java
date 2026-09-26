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

        findings.add(new ScanFinding(
                ScanFinding.Level.INFO,
                "Cobertura do estado de segurança",
                "A leitura por componente é local e não consulta CVEs publicadas nem garante que todas as atualizações disponíveis estejam instaladas. "
                        + "A verificação de CVEs exige uma base OSV carregada separadamente.",
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
