package com.darkshield.security;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ScanHistoryStoreTest {
    @Test
    public void encodeDecodeRoundTripKeepsSummaryFields() {
        List<ScanHistoryStore.Entry> entries = new ArrayList<>();
        entries.add(new ScanHistoryStore.Entry(
                123456L, 47, 1, 2, 3, 4, 10, 20));

        List<ScanHistoryStore.Entry> decoded =
                ScanHistoryStore.decode(ScanHistoryStore.encode(entries));

        assertEquals(1, decoded.size());
        ScanHistoryStore.Entry entry = decoded.get(0);
        assertEquals(123456L, entry.timestampMillis);
        assertEquals(47, entry.score);
        assertEquals(1, entry.critical);
        assertEquals(2, entry.high);
        assertEquals(3, entry.medium);
        assertEquals(4, entry.low);
        assertEquals(10, entry.reviewCount);
        assertEquals(20, entry.totalFindings);
    }

    @Test
    public void historyIsCappedAtTwentyEntries() {
        List<ScanHistoryStore.Entry> entries = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            entries.add(new ScanHistoryStore.Entry(i, i, 0, 0, 0, 0, 0, 0));
        }

        List<ScanHistoryStore.Entry> trimmed = ScanHistoryStore.trim(entries);

        assertEquals(ScanHistoryStore.MAX_ENTRIES, trimmed.size());
        assertEquals(0L, trimmed.get(0).timestampMillis);
        assertEquals(19L, trimmed.get(19).timestampMillis);
    }

    @Test
    public void malformedRowsAreIgnoredAndValuesAreClamped() {
        String encoded = "bad row\n100|999|-1|2|3|4|5|6";

        List<ScanHistoryStore.Entry> decoded = ScanHistoryStore.decode(encoded);

        assertEquals(1, decoded.size());
        assertEquals(100, decoded.get(0).score);
        assertEquals(0, decoded.get(0).critical);
        assertTrue(decoded.get(0).high >= 0);
    }
}
