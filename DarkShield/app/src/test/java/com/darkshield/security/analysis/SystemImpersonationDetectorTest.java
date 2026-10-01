package com.darkshield.security.analysis;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SystemImpersonationDetectorTest {
    @Test public void systemAppIsNeverFlaggedByIdentityHeuristic() {
        assertFalse(SystemImpersonationDetector.inspect(
                "System Update", "com.android.updater", true, null).suspicious());
    }

    @Test public void thirdPartyAndroidNamespaceIsFlagged() {
        SystemImpersonationDetector.Result result =
                SystemImpersonationDetector.inspect(
                        "Updater", "com.android.fakeupdate", false, null);
        assertTrue(result.suspicious());
        assertTrue(result.score >= 5);
    }

    @Test public void trustedSystemLikeLabelWithUnknownInstallerIsFlagged() {
        SystemImpersonationDetector.Result result =
                SystemImpersonationDetector.inspect(
                        "Security Update", "com.example.update", false, null);
        assertTrue(result.suspicious());
        assertTrue(result.score >= 5);
    }

    @Test public void normalPlayStoreAppIsNotFlagged() {
        assertFalse(SystemImpersonationDetector.inspect(
                "Example Notes", "com.example.notes", false,
                "com.android.vending").suspicious());
    }

    @Test public void bidiControlInLabelIsFlagged() {
        assertTrue(SystemImpersonationDetector.inspect(
                "System\u202EUpdate", "com.example.app", false,
                "com.android.vending").suspicious());
    }
}
