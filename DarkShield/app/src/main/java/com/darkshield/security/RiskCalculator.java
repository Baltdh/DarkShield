    public static int score(List<ScanFinding> findings) {
        long points = 0;
        if (findings == null) return 0;
        for (ScanFinding finding : findings) {
            if (finding != null) points += Math.max(0, finding.points);
        }
        return (int) Math.min(100L, points * 3L);
    }