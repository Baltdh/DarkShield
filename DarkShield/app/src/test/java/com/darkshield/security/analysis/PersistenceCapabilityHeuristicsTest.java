package com.darkshield.security.analysis;

import org.junit.Test;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import static org.junit.Assert.*;

public class PersistenceCapabilityHeuristicsTest {
    private Set<String> perms(String... values) {
        return new HashSet<>(Arrays.asList(values));
    }

    @Test public void foregroundServiceCapabilityRecognizesBaseOrTypedPermission() {
        assertTrue(PersistenceCapabilityHeuristics.hasForegroundServiceCapability(
                perms("android.permission.FOREGROUND_SERVICE")));
        assertTrue(PersistenceCapabilityHeuristics.hasForegroundServiceCapability(
                perms("android.permission.FOREGROUND_SERVICE_LOCATION")));
        assertFalse(PersistenceCapabilityHeuristics.hasForegroundServiceCapability(
                Collections.emptySet()));
    }

    @Test public void detectsWakeLockAndExactAlarmCapabilities() {
        assertTrue(PersistenceCapabilityHeuristics.hasWakeLock(
                perms("android.permission.WAKE_LOCK")));
        assertTrue(PersistenceCapabilityHeuristics.hasExactAlarm(
                perms("android.permission.SCHEDULE_EXACT_ALARM")));
        assertTrue(PersistenceCapabilityHeuristics.hasExactAlarm(
                perms("android.permission.USE_EXACT_ALARM")));
    }

    @Test public void sensitiveForegroundTypesAreCountedAndSummarized() {
        Set<String> permissions = perms(
                "android.permission.FOREGROUND_SERVICE_CAMERA",
                "android.permission.FOREGROUND_SERVICE_MICROPHONE",
                "android.permission.FOREGROUND_SERVICE_LOCATION");
        assertEquals(3,
                PersistenceCapabilityHeuristics.sensitiveForegroundServiceTypes(permissions));
        String summary =
                PersistenceCapabilityHeuristics.sensitiveTypeSummary(permissions);
        assertTrue(summary.contains("câmera"));
        assertTrue(summary.contains("microfone"));
        assertTrue(summary.contains("localização"));
    }
}
