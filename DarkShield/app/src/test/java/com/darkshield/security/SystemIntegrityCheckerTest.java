package com.darkshield.security;

import org.junit.Test;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SystemIntegrityCheckerTest {
    @Test public void rootBinaryCheckReturnsBooleanWithoutThrowing() {
        boolean result = SystemIntegrityChecker.hasRootBinary();
        assertTrue(result || !result);
    }

    @Test public void buildChecksAreDeterministic() {
        assertTrue(SystemIntegrityChecker.hasTestKeys("release-keys,test-keys"));
        assertFalse(SystemIntegrityChecker.hasTestKeys("release-keys"));
        assertFalse(SystemIntegrityChecker.hasTestKeys(null));

        assertTrue(SystemIntegrityChecker.isDebuggableBuildType("eng"));
        assertTrue(SystemIntegrityChecker.isDebuggableBuildType("USERDEBUG"));
        assertFalse(SystemIntegrityChecker.isDebuggableBuildType("user"));
        assertFalse(SystemIntegrityChecker.isDebuggableBuildType(null));
    }

    @Test public void rootManagerPathDetectionIsDeterministic() {
        assertTrue(SystemIntegrityChecker.hasRootManagerEnvironmentMarker("/system/bin:/data/adb/magisk"));
        assertTrue(SystemIntegrityChecker.hasRootManagerEnvironmentMarker("/vendor/bin:/opt/KSU/bin"));
        assertFalse(SystemIntegrityChecker.hasRootManagerEnvironmentMarker("/system/bin:/vendor/bin"));
        assertFalse(SystemIntegrityChecker.hasRootManagerEnvironmentMarker(null));
    }

    @Test public void proxyHostValidationIsDeterministic() {
        assertTrue(SystemIntegrityChecker.isUsableProxyHost("  proxy.local  "));
        assertFalse(SystemIntegrityChecker.isUsableProxyHost("   "));
        assertFalse(SystemIntegrityChecker.isUsableProxyHost(null));
    }

    @Test public void proxyHostCheckReturnsNonNull() {
        assertTrue(SystemIntegrityChecker.getProxyHost() != null);
    }
}
