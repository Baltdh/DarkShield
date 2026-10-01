package com.darkshield.security.analysis;

/** Pure scoring helpers for user-facing launcher visibility. */
public final class LauncherVisibilityHeuristics {
    public enum State {
        VISIBLE,
        DECLARED_BUT_DISABLED,
        NO_LAUNCHER_DECLARED,
        UNKNOWN
    }

    private LauncherVisibilityHeuristics() {}

    public static int riskScore(
            boolean systemApp,
            State state,
            boolean bootPersistence,
            boolean accessibilityDeclared,
            boolean overlayGranted,
            boolean installerKnown,
            int sensitiveGranted) {
        if (systemApp || state == null || state == State.VISIBLE || state == State.UNKNOWN) {
            return 0;
        }

        int score = state == State.DECLARED_BUT_DISABLED ? 3 : 0;
        if (bootPersistence) score += 2;
        if (accessibilityDeclared) score += 2;
        if (overlayGranted) score += 2;
        if (!installerKnown) score += 1;
        if (sensitiveGranted >= 2) score += 2;
        else if (sensitiveGranted == 1) score += 1;

        // A background-only app with no launcher is common and should not be
        // reported unless another meaningful signal exists.
        if (state == State.NO_LAUNCHER_DECLARED && score == 0) return 0;
        return Math.min(10, score);
    }
}
