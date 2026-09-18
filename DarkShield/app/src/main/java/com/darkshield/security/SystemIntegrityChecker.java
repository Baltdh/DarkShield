package com.darkshield.security;

import android.os.Build;
import java.io.File;
import java.util.Locale;

public final class SystemIntegrityChecker {
    private static final String[] SU_PATHS = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk", "/system/xbin/daemonsu"
    };

    private static final String[] ROOT_MANAGER_PATHS = {
        "/data/adb/magisk", "/data/adb/ksu", "/data/adb/modules",
        "/sbin/.magisk", "/debug_ramdisk/magisk"
    };

    private SystemIntegrityChecker() {}

    public static boolean hasRootBinary() {
        return existsAny(SU_PATHS);
    }

    public static boolean hasTestKeys() {
        return hasTestKeys(Build.TAGS);
    }

    static boolean hasTestKeys(String tags) {
        return tags != null && tags.toLowerCase(Locale.ROOT).contains("test-keys");
    }

    /**
     * Build.TYPE is available to ordinary apps and is more reliable here than
     * System.getProperty("ro.debuggable"), which normally does not expose
     * Android's system properties to an application process.
     */
    public static boolean hasDebuggableBuild() {
        return isDebuggableBuildType(Build.TYPE);
    }

    static boolean isDebuggableBuildType(String type) {
        String value = type == null ? "" : type.toLowerCase(Locale.ROOT);
        return "eng".equals(value) || "userdebug".equals(value);
    }

    /**
     * Looks for filesystem markers commonly created by root-management tools.
     * These paths are indicators only: absence does not prove an unmodified system.
     */
    public static boolean hasRootManagementMarker() {
        return existsAny(ROOT_MANAGER_PATHS) || hasRootManagerEnvironmentMarker();
    }

    public static String getProxyHost() {
        String host = System.getProperty("http.proxyHost");
        if (!isUsableProxyHost(host)) host = System.getProperty("https.proxyHost");
        return host == null ? "" : host.trim();
    }

    static boolean isUsableProxyHost(String host) {
        return host != null && !host.trim().isEmpty();
    }

    static boolean hasRootManagerEnvironmentMarker(String path) {
        if (path == null || path.trim().isEmpty()) return false;

        String[] entries = path.split(java.util.regex.Pattern.quote(File.pathSeparator));
        for (String entry : entries) {
            if (entry == null) continue;
            String normalized = entry.trim().toLowerCase(Locale.ROOT);
            if (normalized.isEmpty()) continue;

            String[] segments = normalized.split("[/\\\\]+");
            for (String segment : segments) {
                if ("magisk".equals(segment)
                        || ".magisk".equals(segment)
                        || "ksu".equals(segment)
                        || ".ksu".equals(segment)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean existsAny(String[] paths) {
        for (String path : paths) {
            try {
                if (new File(path).exists()) return true;
            } catch (SecurityException ignored) {
                // Keep scanning the remaining indicators.
            }
        }
        return false;
    }

    private static boolean hasRootManagerEnvironmentMarker() {
        try {
            return hasRootManagerEnvironmentMarker(System.getenv("PATH"));
        } catch (SecurityException e) {
            return false;
        }
    }
}
