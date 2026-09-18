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

    public int getRawPoints() {
        long points = 0;
        for (ScanFinding finding : findings) {
            if (finding != null) points += Math.max(0, finding.points);
        }
        return (int) Math.min(Integer.MAX_VALUE, points);
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

    public List<PackageSummary> packageSummaries() {
        java.util.Map<String, PackageSummary> byPackage = new java.util.HashMap<>();
        for (ScanFinding finding : findings) {
            if (finding == null || finding.level == null
                    || finding.level == ScanFinding.Level.INFO
                    || finding.packageName == null || finding.packageName.trim().isEmpty()) {
                continue;
            }

            PackageSummary current = byPackage.get(finding.packageName);
            if (current == null) {
                current = new PackageSummary(finding.packageName, finding.level, 1,
                        Math.max(0, finding.points));
            } else {
                current = current.add(finding);
            }
            byPackage.put(finding.packageName, current);
        }

        List<PackageSummary> result = new ArrayList<>(byPackage.values());
        result.sort((left, right) -> {
            int severity = Integer.compare(right.level.ordinal(), left.level.ordinal());
            if (severity != 0) return severity;
            int points = Integer.compare(right.points, left.points);
            if (points != 0) return points;
            return left.packageName.compareToIgnoreCase(right.packageName);
        });
        return Collections.unmodifiableList(result);
    }

    public String packageSummary() {
        List<PackageSummary> summaries = packageSummaries();
        if (summaries.isEmpty()) return "";

        StringBuilder out = new StringBuilder();
        int shown = Math.min(5, summaries.size());
        for (int i = 0; i < shown; i++) {
            if (i > 0) out.append("\n");
            PackageSummary summary = summaries.get(i);
            out.append(summary.level)
                    .append(" • ")
                    .append(summary.packageName)
                    .append(" • ")
                    .append(summary.findings)
                    .append(" achado(s), ")
                    .append(summary.points)
                    .append(" ponto(s)");
        }
        if (summaries.size() > shown) {
            out.append("\n… e mais ").append(summaries.size() - shown).append(" pacote(s)");
        }
        return out.toString();
    }


    public String informationalDetails() {
        List<ScanFinding> info = new ArrayList<>();
        for (ScanFinding finding : findings) {
            if (finding != null && finding.level == ScanFinding.Level.INFO) {
                info.add(finding);
            }
        }

        info.sort((left, right) -> {
            String leftPackage = left.packageName == null ? "" : left.packageName;
            String rightPackage = right.packageName == null ? "" : right.packageName;
            int packageOrder = leftPackage.compareToIgnoreCase(rightPackage);
            if (packageOrder != 0) return packageOrder;

            String leftTitle = left.title == null ? "" : left.title;
            String rightTitle = right.title == null ? "" : right.title;
            return leftTitle.compareToIgnoreCase(rightTitle);
        });

        StringBuilder out = new StringBuilder();
        for (ScanFinding finding : info) {
            if (out.length() > 0) out.append("\n\n");
            out.append(finding.line());
        }
        return out.toString();
    }

    public String details() {
        List<ScanFinding> review = new ArrayList<>();
        for (ScanFinding finding : findings) {
            if (finding != null && finding.level != null
                    && finding.level != ScanFinding.Level.INFO) {
                review.add(finding);
            }
        }

        review.sort((left, right) -> {
            int severity = Integer.compare(right.level.ordinal(), left.level.ordinal());
            if (severity != 0) return severity;

            int points = Integer.compare(
                    Math.max(0, right.points), Math.max(0, left.points));
            if (points != 0) return points;

            String leftPackage = left.packageName == null ? "" : left.packageName;
            String rightPackage = right.packageName == null ? "" : right.packageName;
            int packageOrder = leftPackage.compareToIgnoreCase(rightPackage);
            if (packageOrder != 0) return packageOrder;

            String leftTitle = left.title == null ? "" : left.title;
            String rightTitle = right.title == null ? "" : right.title;
            return leftTitle.compareToIgnoreCase(rightTitle);
        });

        StringBuilder out = new StringBuilder();
        for (ScanFinding finding : review) {
            if (out.length() > 0) out.append("\n\n");
            out.append(finding.line());
        }
        return out.toString();
    }

    public static final class PackageSummary {
        public final String packageName;
        public final ScanFinding.Level level;
        public final int findings;
        public final int points;

        private PackageSummary(
                String packageName, ScanFinding.Level level, int findings, int points) {
            this.packageName = packageName;
            this.level = level;
            this.findings = findings;
            this.points = points;
        }

        private static int saturatingAdd(int current, int addition) {
            long sum = (long) current + addition;
            return (int) Math.min(Integer.MAX_VALUE, sum);
        }

        private PackageSummary add(ScanFinding finding) {
            ScanFinding.Level higher = finding.level.ordinal() > level.ordinal()
                    ? finding.level : level;
            return new PackageSummary(
                    packageName,
                    higher,
                    findings + 1,
                    saturatingAdd(points, Math.max(0, finding.points)));
        }
    }
}
