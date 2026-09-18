package com.darkshield.security;

import android.os.Build;
import java.io.File;
import java.util.Locale;

public final class SystemIntegrityChecker {
    private static final String[] SU_PATHS = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/app/Superuser.apk"
    };

    private SystemIntegrityChecker() {}

    public static boolean hasRootBinary() {
        for (String path : SU_PATHS) {
            try { if (new File(path).exists()) return true; } catch (SecurityException ignored) {}
        }
        return false;
    }

    public static boolean hasTestKeys() {
        return Build.TAGS != null && Build.TAGS.toLowerCase(Locale.ROOT).contains("test-keys");
    }

    public static boolean hasDebuggableBuild() {
        return "1".equals(getProperty("ro.debuggable"));
    }

    public static boolean hasRootManagementMarker() {
        String[] markers = {"magisk", "supersu", "superuser", "kernelsu"};
        String value = (getProperty("ro.boot.verifiedbootstate") + " " +
                getProperty("ro.boot.flash.locked") + " " +
                getProperty("ro.build.tags")).toLowerCase(Locale.ROOT);
        for (String marker : markers) if (value.contains(marker)) return true;
        return false;
    }

    public static String getProxyHost() {
        String host = System.getProperty("http.proxyHost");
        if (host == null || host.trim().isEmpty()) host = System.getProperty("https.proxyHost");
        return host == null ? "" : host.trim();
    }

    private static String getProperty(String name) {
        try {
            String value = System.getProperty(name);
            return value == null ? "" : value;
        } catch (SecurityException e) {
            return "";
        }
    }
}
