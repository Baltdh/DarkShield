package com.darkshield.security.analysis;

import java.io.File;
import java.util.Locale;

/** Pure scoring helpers for hidden filesystem artifacts. */
public final class HiddenFileHeuristics {
    private HiddenFileHeuristics() {}

    public static boolean isHiddenName(String name) {
        if (name == null) return false;
        String n = name.trim();
        return n.length() > 1 && n.startsWith(".") && !n.equals("..");
    }

    public static boolean hasExecutablePayloadExtension(String name) {
        String n = lower(name);
        return n.endsWith(".apk") || n.endsWith(".jar") || n.endsWith(".dex")
                || n.endsWith(".so") || n.endsWith(".sh") || n.endsWith(".bin");
    }

    public static boolean looksLikeDisguisedPayload(String name) {
        String n = lower(name);
        if (n.isEmpty()) return false;
        return n.matches(".*\\.(jpg|jpeg|png|gif|mp3|mp4|pdf|txt)\\.(apk|jar|dex|so|sh|bin)$")
                || n.matches(".*\\.(apk|jar|dex|so|sh|bin)\\.(jpg|jpeg|png|gif|mp3|mp4|pdf|txt)$");
    }

    public static int riskScore(File file, boolean sharedWritableLocation) {
        if (file == null) return 0;
        String name = file.getName();
        int score = 0;
        if (isHiddenName(name)) score += 1;
        if (hasExecutablePayloadExtension(name)) score += 2;
        if (looksLikeDisguisedPayload(name)) score += 4;
        if (sharedWritableLocation && hasExecutablePayloadExtension(name)) score += 2;
        if (file.canExecute() && !file.isDirectory()) score += 2;
        return Math.min(10, score);
    }

    public static boolean shouldReport(File file, boolean sharedWritableLocation) {
        return riskScore(file, sharedWritableLocation) >= 4;
    }

    private static String lower(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
