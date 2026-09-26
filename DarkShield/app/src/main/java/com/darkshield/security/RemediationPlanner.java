package com.darkshield.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Converts findings into Android settings screens the user can review.
 */
public final class RemediationPlanner {
    public enum Kind {
        ACCESSIBILITY,
        NOTIFICATIONS,
        OVERLAY,
        WRITE_SETTINGS,
        UNKNOWN_SOURCES,
        USAGE_ACCESS,
        SECURITY,
        BATTERY,
        VPN,
        DEFAULT_APPS,
        INPUT_METHOD,
        APP_DETAILS
    }

    public static final class Action {
        public final String packageName;
        public final String title;
        public final String reason;
        public final Kind kind;

        Action(String packageName, String title, String reason, Kind kind) {
            this.packageName = packageName;
            this.title = title;
            this.reason = reason;
            this.kind = kind;
        }
    }

    private RemediationPlanner() {}

    public static List<Action> plan(List<ScanFinding> findings) {
        List<Action> result = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        if (findings == null) return result;

        List<ScanFinding> ordered = new ArrayList<>(findings);
        ordered.removeAll(Collections.singleton(null));
        ordered.sort(Comparator.comparingInt((ScanFinding f) ->
                f.level == null ? -1 : f.level.ordinal()).reversed());
        for (ScanFinding f : ordered) {
            if (f == null || f.level == null || f.level == ScanFinding.Level.INFO
                    || f.packageName == null || f.packageName.trim().isEmpty()) {
                continue;
            }

            String pkg = f.packageName.trim();
            String title = f.title == null ? "" : f.title.toLowerCase(Locale.ROOT);
            Kind kind;
            if (title.contains("acessibilidade")) {
                kind = Kind.ACCESSIBILITY;
            } else if (title.contains("notifica")) {
                kind = Kind.NOTIFICATIONS;
            } else if (title.contains("sobreposição")) {
                kind = Kind.OVERLAY;
            } else if (title.contains("write_settings")
                    || title.contains("modificar configurações")) {
                kind = Kind.WRITE_SETTINGS;
            } else if (title.contains("instalação de apk")) {
                kind = Kind.UNKNOWN_SOURCES;
            } else if (title.contains("dados de uso")) {
                kind = Kind.USAGE_ACCESS;
            } else if (title.contains("administrador")) {
                kind = Kind.SECURITY;
            } else if (title.contains("otimização de bateria")) {
                kind = Kind.BATTERY;
            } else if (title.contains("vpn")) {
                kind = Kind.VPN;
            } else if (title.contains("aplicativo padrão")) {
                kind = Kind.DEFAULT_APPS;
            } else if (title.contains("teclado")) {
                kind = Kind.INPUT_METHOD;
            } else {
                kind = Kind.APP_DETAILS;
            }

            // Keep different grants for the same package; collapse repeated general
            // findings into a single application-details action.
            if (!seen.add(pkg + "|" + kind)) continue;
            result.add(new Action(
                    pkg,
                    "Revisar " + (f.title == null ? "aplicativo" : f.title) + " • " + pkg,
                    f.detail == null ? "Indicador que merece revisão." : f.detail,
                    kind));
            if (result.size() >= 40) break;
        }
        return result;
    }
}
