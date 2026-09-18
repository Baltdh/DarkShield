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
        return Build.TAGS != null && Build.TAGS.toLowerCase(Locale.ROOT).contains("test-keys");
    }

    /**
     * Build.TYPE is available to ordinary apps and is more reliable here than
     * System.getProperty("ro.debuggable"), which normally does not expose
     * Android's system properties to an application process.
     */
    public static boolean hasDebuggableBuild() {
        String type = Build.TYPE == null ? "" : Build.TYPE.toLowerCase(Locale.ROOT);
        return "eng".equals(type) || "userdebug".equals(type);
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
        if (host == null || host.trim().isEmpty()) host = System.getProperty("https.proxyHost");
        return host == null ? "" : host.trim();
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
            String path = System.getenv("PATH");
            if (path == null) return false;
            String value = path.toLowerCase(Locale.ROOT);
            return value.contains("magisk") || value.contains("ksu");
        } catch (SecurityException e) {
            return false;
        }
    }
}
