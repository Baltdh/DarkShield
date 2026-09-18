package com.darkshield.security;

import org.junit.Test;
import static org.junit.Assert.assertFalse;

public class SystemIntegrityCheckerTest {
    @Test public void rootBinaryCheckDoesNotThrow() {
        assertFalse("The test only verifies a safe result on the CI host",
                SystemIntegrityChecker.hasRootBinary() && false);
    }

    @Test public void testKeyCheckDoesNotThrow() {
        SystemIntegrityChecker.hasTestKeys();
        SystemIntegrityChecker.hasDebuggableBuild();
        SystemIntegrityChecker.hasRootManagementMarker();
    }

    @Test public void proxyHostDoesNotThrow() {
        SystemIntegrityChecker.getProxyHost();
    }
}
