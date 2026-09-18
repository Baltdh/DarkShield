package com.darkshield.security;

import org.junit.Test;
import static org.junit.Assert.assertNotNull;

public class SystemIntegrityCheckerTest {
    @Test public void rootBinaryCheckReturnsBooleanWithoutThrowing() {
        boolean result = SystemIntegrityChecker.hasRootBinary();
        assertNotNull(Boolean.valueOf(result));
    }

    @Test public void buildChecksReturnBooleanWithoutThrowing() {
        boolean testKeys = SystemIntegrityChecker.hasTestKeys();
        boolean debuggable = SystemIntegrityChecker.hasDebuggableBuild();
        boolean rootMarker = SystemIntegrityChecker.hasRootManagementMarker();
        assertNotNull(Boolean.valueOf(testKeys));
        assertNotNull(Boolean.valueOf(debuggable));
        assertNotNull(Boolean.valueOf(rootMarker));
    }

    @Test public void proxyHostIsNeverNull() {
        assertNotNull(SystemIntegrityChecker.getProxyHost());
    }
}
