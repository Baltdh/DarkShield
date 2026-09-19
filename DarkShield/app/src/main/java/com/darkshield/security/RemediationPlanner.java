package com.darkshield.security;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Converts findings into safe, user-confirmed remediation targets.
 * It never changes settings or removes an app by itself.
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
        APP_DETAILS
    }

    public static final class Action {
        public final String packageName;
        public final String title;
        public final String reason;
        public final Kind kind;
        public final boolean uninstallCandidate;

        Action(String packageName, String title, String reason, Kind kind, boolean uninstallCandidate) {
            this.packageName = packageName;
            this.title = title;
            this.reason = reason;
            this.kind = kind;
            this.uninstallCandidate = uninstallCandidate;
        }
    }

    private RemediationPlanner() {}

    public static List<Action> plan(List<ScanFinding> findings) {
        List<Action> result = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        if (findings == null) return result;

        for (ScanFinding f : findings) {
            if (f == null || f.level == null || f.level == ScanFinding.Level.INFO
                    || f.packageName == null || f.packageName.trim().isEmpty()) {
                continue;
            }

            String pkg = f.packageName.trim();
            String key = f.level + "|" + pkg;
            if (!seen.add(key)) continue;

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
            } else {
                kind = Kind.APP_DETAILS;
            }

            boolean uninstallCandidate = f.level == ScanFinding.Level.CRITICAL
                    || f.level == ScanFinding.Level.HIGH;
            result.add(new Action(
                    pkg,
                    "Revisar " + pkg,
                    f.detail == null ? "Indicador que merece revisão." : f.detail,
                    kind,
                    uninstallCandidate));
            if (result.size() >= 8) break;
        }
        return result;
    }
}
