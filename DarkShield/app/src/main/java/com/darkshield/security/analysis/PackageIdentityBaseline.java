package com.darkshield.security.analysis;

import java.util.Locale;

/**
 * Pure comparison helpers for package identity history. Persistence is kept in
 * SecurityScanner so these rules remain JVM-testable without Android framework
 * dependencies.
 */
public final class PackageIdentityBaseline {
    public enum SignerChange {
        NONE,
        LEGITIMATE_ROTATION,
        UNEXPECTED_CHANGE
    }

    private PackageIdentityBaseline() {}

    public static SignerChange compareSigner(
            String previousSigner,
            String currentSigner,
            boolean previousSignerInCurrentLineage) {
        String previous = normalize(previousSigner);
        String current = normalize(currentSigner);
        if (previous == null || current == null || previous.equals(current)) {
            return SignerChange.NONE;
        }
        return previousSignerInCurrentLineage
                ? SignerChange.LEGITIMATE_ROTATION
                : SignerChange.UNEXPECTED_CHANGE;
    }

    public static boolean isDowngrade(long previousVersion, long currentVersion) {
        return previousVersion >= 0L
                && currentVersion >= 0L
                && currentVersion < previousVersion;
    }

    public static boolean installerChanged(String previousInstaller, String currentInstaller) {
        String previous = normalize(previousInstaller);
        String current = normalize(currentInstaller);
        // Unknown installer values are intentionally ignored: backups, device
        // migration and OEM PackageInstaller behavior can legitimately erase
        // attribution.
        return previous != null && current != null && !previous.equals(current);
    }

    public static boolean shouldUpdateSignerBaseline(
            String previousSigner,
            String currentSigner,
            boolean previousSignerInCurrentLineage) {
        String current = normalize(currentSigner);
        if (current == null) return false;
        return compareSigner(
                previousSigner, currentSigner, previousSignerInCurrentLineage)
                != SignerChange.UNEXPECTED_CHANGE;
    }

    public static boolean shouldUpdateVersionBaseline(
            long previousVersion, long currentVersion) {
        return currentVersion >= 0L && !isDowngrade(previousVersion, currentVersion);
    }

    public static boolean shouldUpdateInstallerBaseline(
            String previousInstaller, String currentInstaller) {
        String current = normalize(currentInstaller);
        return current != null && !installerChanged(previousInstaller, currentInstaller);
    }

    static String normalize(String value) {
        if (value == null) return null;
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return normalized.isEmpty() ? null : normalized;
    }
}
