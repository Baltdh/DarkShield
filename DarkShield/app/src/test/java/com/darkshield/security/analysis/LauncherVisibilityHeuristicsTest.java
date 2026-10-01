package com.darkshield.security.analysis;

import org.junit.Test;
import static org.junit.Assert.*;

public class LauncherVisibilityHeuristicsTest {
    @Test public void visibleAppsDoNotGainRisk() {
        assertEquals(0, LauncherVisibilityHeuristics.riskScore(
                false,
                LauncherVisibilityHeuristics.State.VISIBLE,
                true, true, true, false, 4));
    }

    @Test public void backgroundOnlyAppNeedsCorroboration() {
        assertEquals(0, LauncherVisibilityHeuristics.riskScore(
                false,
                LauncherVisibilityHeuristics.State.NO_LAUNCHER_DECLARED,
                false, false, false, true, 0));

        assertTrue(LauncherVisibilityHeuristics.riskScore(
                false,
                LauncherVisibilityHeuristics.State.NO_LAUNCHER_DECLARED,
                true, true, false, true, 1) >= 4);
    }

    @Test public void disabledLauncherStartsAsMeaningfulEvasionSignal() {
        assertEquals(3, LauncherVisibilityHeuristics.riskScore(
                false,
                LauncherVisibilityHeuristics.State.DECLARED_BUT_DISABLED,
                false, false, false, true, 0));
    }

    @Test public void disabledLauncherWithPrivilegesCanBecomeHighRisk() {
        assertEquals(10, LauncherVisibilityHeuristics.riskScore(
                false,
                LauncherVisibilityHeuristics.State.DECLARED_BUT_DISABLED,
                true, true, true, false, 3));
    }

    @Test public void systemAppsAreSuppressedFromThisHeuristic() {
        assertEquals(0, LauncherVisibilityHeuristics.riskScore(
                true,
                LauncherVisibilityHeuristics.State.DECLARED_BUT_DISABLED,
                true, true, true, false, 5));
    }
}
