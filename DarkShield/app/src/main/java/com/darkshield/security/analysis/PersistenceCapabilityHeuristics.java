package com.darkshield.security.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Pure helpers for Android background/foreground persistence capabilities. */
public final class PersistenceCapabilityHeuristics {
    private static final String FOREGROUND = "android.permission.FOREGROUND_SERVICE";
    private static final String FOREGROUND_PREFIX = "android.permission.FOREGROUND_SERVICE_";
    private static final String WAKE_LOCK = "android.permission.WAKE_LOCK";
    private static final String SCHEDULE_EXACT_ALARM = "android.permission.SCHEDULE_EXACT_ALARM";
    private static final String USE_EXACT_ALARM = "android.permission.USE_EXACT_ALARM";

    private PersistenceCapabilityHeuristics() {}

    public static boolean hasForegroundServiceCapability(Set<String> permissions) {
        if (permissions == null || permissions.isEmpty()) return false;
        if (permissions.contains(FOREGROUND)) return true;
        for (String permission : permissions) {
            if (permission != null && permission.startsWith(FOREGROUND_PREFIX)) return true;
        }
        return false;
    }

    public static boolean hasWakeLock(Set<String> permissions) {
        return permissions != null && permissions.contains(WAKE_LOCK);
    }

    public static boolean hasExactAlarm(Set<String> permissions) {
        return permissions != null
                && (permissions.contains(SCHEDULE_EXACT_ALARM)
                    || permissions.contains(USE_EXACT_ALARM));
    }

    public static int sensitiveForegroundServiceTypes(Set<String> permissions) {
        if (permissions == null) return 0;
        int count = 0;
        if (permissions.contains("android.permission.FOREGROUND_SERVICE_CAMERA")) count++;
        if (permissions.contains("android.permission.FOREGROUND_SERVICE_MICROPHONE")) count++;
        if (permissions.contains("android.permission.FOREGROUND_SERVICE_LOCATION")) count++;
        if (permissions.contains("android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION")) count++;
        if (permissions.contains("android.permission.FOREGROUND_SERVICE_HEALTH")) count++;
        return count;
    }

    public static String sensitiveTypeSummary(Set<String> permissions) {
        if (permissions == null) return "";
        List<String> names = new ArrayList<>();
        if (permissions.contains("android.permission.FOREGROUND_SERVICE_CAMERA")) names.add("câmera");
        if (permissions.contains("android.permission.FOREGROUND_SERVICE_MICROPHONE")) names.add("microfone");
        if (permissions.contains("android.permission.FOREGROUND_SERVICE_LOCATION")) names.add("localização");
        if (permissions.contains("android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION")) names.add("captura/projeção de tela");
        if (permissions.contains("android.permission.FOREGROUND_SERVICE_HEALTH")) names.add("saúde/sensores");
        return String.join(", ", names);
    }
}
