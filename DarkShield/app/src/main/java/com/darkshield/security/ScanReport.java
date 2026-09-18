package com.darkshield.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class ScanReport {
    private final List<ScanFinding> findings;

    public ScanReport(List<ScanFinding> findings) {
        this.findings = findings == null
                ? Collections.emptyList()
                : Collections.unmodifiableList(new ArrayList<>(findings));
    }

    public List<ScanFinding> getFindings() {
        return findings;
    }

    public int getScore() {
        return RiskCalculator.score(findings);
    }

    public String getStatus() {
        return RiskCalculator.status(findings);
    }

    public int count(ScanFinding.Level level) {
        if (level == null) return 0;
        int total = 0;
        for (ScanFinding finding : findings) {
            if (finding != null && finding.level == level) total++;
        }
        return total;
    }

    public int countRequiringReview() {
        int total = 0;
        for (ScanFinding finding : findings) {
            if (finding != null && finding.level != ScanFinding.Level.INFO) total++;
        }
        return total;
    }

    public String details() {
        StringBuilder out = new StringBuilder();
        for (ScanFinding finding : findings) {
            if (finding == null || finding.level == ScanFinding.Level.INFO) continue;
            if (out.length() > 0) out.append("\n\n");
            out.append(finding.line());
        }
        return out.toString();
    }
}
