package com.darkshield.security;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

public final class ScanFinding {
    public enum Level { INFO, LOW, MEDIUM, HIGH, CRITICAL }

    public enum EvidenceSource {
        UNKNOWN,
        OBSERVED,
        DECLARED,
        HEURISTIC,
        DERIVED,
        ANALYSIS_LIMIT
    }

    public enum EvidenceTag {
        ACTIVE_ACCESS,
        PERSISTENCE,
        REMOTE_CONTROL,
        SENSITIVE_DATA,
        INSTALL_TRUST,
        STATIC_ANALYSIS,
        VULNERABILITY,
        CORRELATION,
        ANALYSIS_GAP
    }

    public final Level level;
    public final String title;
    public final String detail;
    public final String packageName;
    public final int points;
    public final String action;
    public final EvidenceSource evidenceSource;
    public final Set<EvidenceTag> evidenceTags;

    public ScanFinding(
            Level level,
            String title,
            String detail,
            String packageName,
            int points,
            String action) {
        this(level, title, detail, packageName, points, action,
                EvidenceSource.UNKNOWN, Collections.emptySet());
    }

    public ScanFinding(
            Level level,
            String title,
            String detail,
            String packageName,
            int points,
            String action,
            Set<EvidenceTag> evidenceTags) {
        this(level, title, detail, packageName, points, action,
                EvidenceSource.UNKNOWN, evidenceTags);
    }

    public ScanFinding(
            Level level,
            String title,
            String detail,
            String packageName,
            int points,
            String action,
            EvidenceSource evidenceSource,
            Set<EvidenceTag> evidenceTags) {
        this.level = level;
        this.title = title;
        this.detail = detail;
        this.packageName = packageName;
        this.points = points;
        this.action = action;
        this.evidenceSource = evidenceSource == null
                ? EvidenceSource.UNKNOWN : evidenceSource;
        if (evidenceTags == null || evidenceTags.isEmpty()) {
            this.evidenceTags = Collections.emptySet();
        } else {
            this.evidenceTags = Collections.unmodifiableSet(EnumSet.copyOf(evidenceTags));
        }
    }

    public ScanFinding withTags(EvidenceTag... tags) {
        if (tags == null || tags.length == 0) return this;

        EnumSet<EvidenceTag> merged = evidenceTags.isEmpty()
                ? EnumSet.noneOf(EvidenceTag.class)
                : EnumSet.copyOf(evidenceTags);
        for (EvidenceTag tag : tags) {
            if (tag != null) merged.add(tag);
        }
        if (merged.equals(evidenceTags)) return this;
        return new ScanFinding(
                level, title, detail, packageName, points, action, evidenceSource, merged);
    }

    public ScanFinding withEvidence(EvidenceSource source, EvidenceTag... tags) {
        ScanFinding tagged = withTags(tags);
        EvidenceSource resolved = source == null ? EvidenceSource.UNKNOWN : source;
        if (tagged.evidenceSource == resolved) return tagged;
        return new ScanFinding(
                tagged.level,
                tagged.title,
                tagged.detail,
                tagged.packageName,
                tagged.points,
                tagged.action,
                resolved,
                tagged.evidenceTags);
    }

    public boolean hasEvidenceTag(EvidenceTag tag) {
        return tag != null && evidenceTags.contains(tag);
    }

    public String line() {
        StringBuilder b = new StringBuilder();
        b.append("[").append(level).append("] ").append(title).append("\n");
        b.append("    ").append(detail);
        if (packageName != null) b.append("\n    pacote: ").append(packageName);
        if (points > 0) b.append("\n    impacto heurístico: +").append(points).append(" ponto(s)");
        if (action != null) b.append("\n    ação: ").append(action);
        return b.toString();
    }
}
