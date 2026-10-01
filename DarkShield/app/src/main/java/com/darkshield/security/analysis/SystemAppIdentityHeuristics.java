package com.darkshield.security.analysis;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Pure heuristics for spotting user-installed apps that impersonate Android,
 * Google or device/OEM system components. A name match is never treated as
 * malware by itself; callers must correlate it with provenance/capabilities.
 */
public final class SystemAppIdentityHeuristics {
    private static final Set<String> GENERIC_SYSTEM_LABELS = new HashSet<>(Arrays.asList(
            "system update", "software update", "security update", "android update",
            "system service", "android service", "google service", "google services",
            "device service", "device services", "settings", "package installer",
            "system ui", "systemui"
    ));

    private SystemAppIdentityHeuristics() {}

    public static boolean claimsSystemIdentity(
            String label, String packageName, String manufacturer, String brand) {
        String l = normalize(label);
        String p = normalize(packageName);
        if (l == null && p == null) return false;

        if (l != null && GENERIC_SYSTEM_LABELS.contains(l)) return true;

        if (p != null && (p.startsWith("com.android.")
                || p.startsWith("android.")
                || p.startsWith("com.google.android."))) {
            return true;
        }

        String maker = compact(manufacturer);
        String deviceBrand = compact(brand);
        String compactLabel = compact(label);
        String compactPackage = compact(packageName);

        return claimsOem(compactLabel, compactPackage, maker)
                || (!deviceBrand.equals(maker)
                    && claimsOem(compactLabel, compactPackage, deviceBrand));
    }

    public static int impersonationRisk(
            boolean systemApp,
            boolean claimsSystemIdentity,
            boolean installerKnown,
            int sensitiveGranted,
            boolean accessibilityDeclared,
            boolean overlayGranted,
            boolean canInstallPackages) {
        if (systemApp || !claimsSystemIdentity) return 0;

        int score = 2; // Identity mismatch alone remains a weak signal.
        if (!installerKnown) score += 2;
        if (sensitiveGranted >= 2) score += 2;
        else if (sensitiveGranted == 1) score += 1;
        if (accessibilityDeclared) score += 2;
        if (overlayGranted) score += 2;
        if (canInstallPackages) score += 2;
        return Math.min(10, score);
    }

    private static boolean claimsOem(String label, String pkg, String oem) {
        if (oem.length() < 3) return false;
        boolean labelClaim = !label.isEmpty()
                && (label.equals(oem)
                    || label.startsWith(oem + "system")
                    || label.startsWith(oem + "security")
                    || label.startsWith(oem + "update")
                    || label.startsWith(oem + "service"));
        boolean packageClaim = !pkg.isEmpty()
                && (pkg.startsWith("com" + oem)
                    || pkg.startsWith(oem + "android")
                    || pkg.startsWith(oem + "system"));
        return labelClaim || packageClaim;
    }

    private static String normalize(String value) {
        if (value == null) return null;
        String out = value.trim().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
        return out.isEmpty() ? null : out;
    }

    private static String compact(String value) {
        String normalized = normalize(value);
        return normalized == null ? "" : normalized.replaceAll("[^a-z0-9]", "");
    }
}
