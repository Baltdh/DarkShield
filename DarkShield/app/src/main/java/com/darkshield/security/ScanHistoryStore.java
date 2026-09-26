package com.darkshield.security;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class ScanHistoryStore {
    static final int MAX_ENTRIES = 20;
    private static final String PREFS = "darkshield_scan_history";
    private static final String KEY_HISTORY = "entries";

    public static final class Entry {
        public final long timestampMillis;
        public final int score;
        public final int critical;
        public final int high;
        public final int medium;
        public final int low;
        public final int reviewCount;
        public final int totalFindings;

        Entry(
                long timestampMillis,
                int score,
                int critical,
                int high,
                int medium,
                int low,
                int reviewCount,
                int totalFindings) {
            this.timestampMillis = Math.max(0L, timestampMillis);
            this.score = clamp(score, 0, 100);
            this.critical = Math.max(0, critical);
            this.high = Math.max(0, high);
            this.medium = Math.max(0, medium);
            this.low = Math.max(0, low);
            this.reviewCount = Math.max(0, reviewCount);
            this.totalFindings = Math.max(0, totalFindings);
        }
    }

    private ScanHistoryStore() {}

    public static void record(Context context, ScanReport report, long timestampMillis) {
        if (context == null || report == null) return;

        Entry entry = new Entry(
                timestampMillis,
                report.getScore(),
                report.count(ScanFinding.Level.CRITICAL),
                report.count(ScanFinding.Level.HIGH),
                report.count(ScanFinding.Level.MEDIUM),
                report.count(ScanFinding.Level.LOW),
                report.countRequiringReview(),
                report.getFindings().size());

        List<Entry> entries = new ArrayList<>(load(context));
        entries.add(0, entry);
        entries = trim(entries);

        context.getApplicationContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_HISTORY, encode(entries))
                .apply();
    }

    public static List<Entry> load(Context context) {
        if (context == null) return Collections.emptyList();
        SharedPreferences prefs = context.getApplicationContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        return Collections.unmodifiableList(decode(prefs.getString(KEY_HISTORY, "")));
    }

    public static void clear(Context context) {
        if (context == null) return;
        context.getApplicationContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .remove(KEY_HISTORY)
                .apply();
    }

    static List<Entry> trim(List<Entry> entries) {
        if (entries == null || entries.isEmpty()) return Collections.emptyList();
        int size = Math.min(MAX_ENTRIES, entries.size());
        return new ArrayList<>(entries.subList(0, size));
    }

    static String encode(List<Entry> entries) {
        if (entries == null || entries.isEmpty()) return "";
        StringBuilder out = new StringBuilder();
        int written = 0;
        for (Entry entry : entries) {
            if (entry == null || written >= MAX_ENTRIES) continue;
            if (out.length() > 0) out.append('\n');
            out.append(entry.timestampMillis).append('|')
                    .append(entry.score).append('|')
                    .append(entry.critical).append('|')
                    .append(entry.high).append('|')
                    .append(entry.medium).append('|')
                    .append(entry.low).append('|')
                    .append(entry.reviewCount).append('|')
                    .append(entry.totalFindings);
            written++;
        }
        return out.toString();
    }

    static List<Entry> decode(String encoded) {
        List<Entry> entries = new ArrayList<>();
        if (encoded == null || encoded.trim().isEmpty()) return entries;

        String[] lines = encoded.split("\\n");
        for (String line : lines) {
            if (entries.size() >= MAX_ENTRIES) break;
            String[] fields = line.split("\\|", -1);
            if (fields.length != 8) continue;
            try {
                entries.add(new Entry(
                        Long.parseLong(fields[0]),
                        Integer.parseInt(fields[1]),
                        Integer.parseInt(fields[2]),
                        Integer.parseInt(fields[3]),
                        Integer.parseInt(fields[4]),
                        Integer.parseInt(fields[5]),
                        Integer.parseInt(fields[6]),
                        Integer.parseInt(fields[7])));
            } catch (NumberFormatException ignored) {
                // Ignore corrupt history rows and preserve valid entries.
            }
        }
        return entries;
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }
}
