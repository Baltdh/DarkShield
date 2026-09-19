package com.darkshield.security;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class ScanTimingTrackerTest {
    @Test public void slowestReturnsLargestDuration() {
        ScanTimingTracker tracker = new ScanTimingTracker();
        tracker.record("com.example.fast", 10);
        tracker.record("com.example.slow", 250);
        tracker.record("com.example.medium", 80);

        ScanTimingTracker.Entry slowest = tracker.slowest();

        assertEquals("com.example.slow", slowest.packageName);
        assertEquals(250L, slowest.durationMillis);
    }

    @Test public void slowestListIsBoundedAndSorted() {
        ScanTimingTracker tracker = new ScanTimingTracker();
        tracker.record("a", 20);
        tracker.record("b", 200);
        tracker.record("c", 100);

        List<ScanTimingTracker.Entry> result = tracker.slowest(2);

        assertEquals(2, result.size());
        assertEquals("b", result.get(0).packageName);
        assertEquals("c", result.get(1).packageName);
    }

    @Test public void invalidPackageNamesAreIgnored() {
        ScanTimingTracker tracker = new ScanTimingTracker();
        tracker.record(null, 100);
        tracker.record("  ", 200);

        assertEquals(0, tracker.size());
        assertNull(tracker.slowest());
    }

    @Test public void negativeDurationIsClamped() {
        ScanTimingTracker tracker = new ScanTimingTracker();
        tracker.record("com.example.app", -50);

        assertEquals(0L, tracker.slowest().durationMillis);
    }
}
