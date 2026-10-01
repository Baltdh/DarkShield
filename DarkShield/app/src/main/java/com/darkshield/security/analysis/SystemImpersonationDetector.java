package com.darkshield.security.analysis;

import java.text.Normalizer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Conservative heuristics for third-party apps that imitate trusted Android
 * or platform component identities. These rules are signals only and should
 * be correlated with installer, privileges and package integrity.
 */
public final class SystemImpersonationDetector {
    private SystemImpersonationDetector() {}

    private static final Set<String> SYSTEM_LIKE_LABELS = new HashSet<>(Arrays.asList(
            "android system",
            "system update",
            "security update",
            "system ui",
            "package installer",
            "android services",
            "phone services",
            "google play services",
            "google play store",
            "settings"
    ));

    public static Result inspect(
            String label,
            String packageName,
            boolean systemApp,
            String installerPackage) {
        if (systemApp) return Result.none();

        String normalizedLabel = normalize(label);
        String normalizedPackage = packageName == null
                ? "" : packageName.trim().toLowerCase(Locale.ROOT);
        String installer = installerPackage == null
                ? "" : installerPackage.trim().toLowerCase(Locale.ROOT);

        boolean platformNamespace = normalizedPackage.equals("android")
                || normalizedPackage.startsWith("android.")
                || normalizedPackage.startsWith("com.android.");
        boolean trustedLabel = SYSTEM_LIKE_LABELS.contains(normalizedLabel);
        boolean deceptiveUnicode = hasDeceptiveUnicode(label);
        boolean unknownInstaller = installer.isEmpty();
        boolean nonPlayInstaller = !installer.isEmpty()
                && !installer.equals("com.android.vending");

        int score = 0;
        if (platformNamespace) score += 5;
        if (trustedLabel) score += 3;
        if (deceptiveUnicode) score += 3;
        if ((platformNamespace || trustedLabel) && unknownInstaller) score += 2;
        if ((platformNamespace || trustedLabel) && nonPlayInstaller) score += 1;

        if (score <= 0) return Result.none();

        StringBuilder reason = new StringBuilder();
        if (platformNamespace) append(reason, "namespace semelhante ao Android");
        if (trustedLabel) append(reason, "nome semelhante a componente confiável");
        if (deceptiveUnicode) append(reason, "caracteres Unicode potencialmente enganosos");
        if (unknownInstaller) append(reason, "origem de instalação não identificada");
        else if (nonPlayInstaller) append(reason, "instalador diferente da Play Store");

        return new Result(score, reason.toString());
    }

    static String normalize(String value) {
        if (value == null) return "";
        String normalized = Normalizer.normalize(value, Normalizer.Form.NFKC)
                .toLowerCase(Locale.ROOT)
                .trim()
                .replaceAll("\\s+", " ");
        return normalized;
    }

    static boolean hasDeceptiveUnicode(String value) {
        if (value == null || value.isEmpty()) return false;
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            int type = Character.getType(ch);
            if (type == Character.FORMAT) return true;
            if (ch == '\u202A' || ch == '\u202B' || ch == '\u202D'
                    || ch == '\u202E' || ch == '\u202C'
                    || ch == '\u2066' || ch == '\u2067'
                    || ch == '\u2068' || ch == '\u2069') {
                return true;
            }
        }
        return false;
    }

    private static void append(StringBuilder out, String part) {
        if (out.length() > 0) out.append(", ");
        out.append(part);
    }

    public static final class Result {
        public final int score;
        public final String reason;

        private Result(int score, String reason) {
            this.score = score;
            this.reason = reason;
        }

        static Result none() {
            return new Result(0, "");
        }

        public boolean suspicious() {
            return score > 0;
        }
    }
}
