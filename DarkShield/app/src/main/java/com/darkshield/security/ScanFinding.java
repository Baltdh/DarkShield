package com.darkshield.security;

public final class ScanFinding {
    public enum Level { INFO, LOW, MEDIUM, HIGH, CRITICAL }
    public final Level level;
    public final String title;
    public final String detail;
    public final String packageName;
    public final int points;
    public final String action;

    public ScanFinding(Level level, String title, String detail, String packageName, int points, String action) {
        this.level = level;
        this.title = title;
        this.detail = detail;
        this.packageName = packageName;
        this.points = points;
        this.action = action;
    }

    public String line() {
        StringBuilder b = new StringBuilder();
        b.append("[").append(level).append("] ").append(title).append("\n");
        b.append("    ").append(detail);
        if (packageName != null) b.append("\n    pacote: ").append(packageName);
        if (action != null) b.append("\n    ação: ").append(action);
        return b.toString();
    }
}