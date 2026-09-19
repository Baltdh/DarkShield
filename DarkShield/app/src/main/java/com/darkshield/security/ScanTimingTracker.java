package com.darkshield.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Collects lightweight per-package scan timings for diagnostics.
 * It never affects risk scoring or scan decisions.
 */
public final class ScanTimingTracker {
    private final List<Entry> entries = new ArrayList<>();

    public void record(String packageName, long durationMillis) {
        if (packageName == null || packageName.trim().isEmpty()) return;
        entries.add(new Entry(packageName, Math.max(0L, durationMillis)));
    }

    public int size() {
        return entries.size();
    }

    public Entry slowest() {
        Entry slowest = null;
        for (Entry entry : entries) {
            if (slowest == null || entry.durationMillis > slowest.durationMillis) {
                slowest = entry;
            }
        }
        return slowest;
    }

    public List<Entry> slowest(int limit) {
        if (limit <= 0 || entries.isEmpty()) return Collections.emptyList();
        List<Entry> result = new ArrayList<>(entries);
        result.sort(Comparator.comparingLong((Entry entry) -> entry.durationMillis).reversed());
        if (result.size() > limit) {
            result = new ArrayList<>(result.subList(0, limit));
        }
        return Collections.unmodifiableList(result);
    }

    public static final class Entry {
        public final String packageName;
        public final long durationMillis;

        public Entry(String packageName, long durationMillis) {
            this.packageName = packageName;
            this.durationMillis = durationMillis;
        }
    }
}
