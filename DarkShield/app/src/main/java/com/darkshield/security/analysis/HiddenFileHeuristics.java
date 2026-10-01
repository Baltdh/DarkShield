package com.darkshield.security.analysis;

import java.io.File;
import java.util.Locale;

/** Pure scoring helpers for hidden filesystem artifacts. */
public final class HiddenFileHeuristics {
    public enum ExecutableMagic { NONE, DEX, ELF }

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


    public static ExecutableMagic detectExecutableMagic(byte[] header) {
        if (header == null || header.length < 4) return ExecutableMagic.NONE;
        if ((header[0] == 'd' && header[1] == 'e' && header[2] == 'x' && header[3] == '\n')
                || (header[0] == 'd' && header[1] == 'e' && header[2] == 'y' && header[3] == '\n')
                || (header[0] == 'v' && header[1] == 'd' && header[2] == 'e' && header[3] == 'x')) {
            return ExecutableMagic.DEX;
        }
        if ((header[0] & 0xFF) == 0x7F
                && header[1] == 'E' && header[2] == 'L' && header[3] == 'F') {
            return ExecutableMagic.ELF;
        }
        return ExecutableMagic.NONE;
    }

    public static int magicRisk(String name, byte[] header) {
        ExecutableMagic kind = detectExecutableMagic(header);
        if (kind == ExecutableMagic.NONE) return 0;
        String n = lower(name);
        boolean expected = kind == ExecutableMagic.DEX
                ? n.endsWith(".dex") || n.endsWith(".odex") || n.endsWith(".vdex")
                : n.endsWith(".so") || n.endsWith(".bin");
        return expected ? 2 : 5;
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
