package com.darkshield.security;

import org.junit.Test;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class SecurityBaselineStoreTest {
    @Test
    public void baselineTracksOnlyObservedSecurityTags() {
        List<ScanFinding> findings = Arrays.asList(
                new ScanFinding(ScanFinding.Level.HIGH, "observed", "x", "pkg", 8, null)
                        .withEvidence(
                                ScanFinding.EvidenceSource.OBSERVED,
                                ScanFinding.EvidenceTag.ACTIVE_ACCESS,
                                ScanFinding.EvidenceTag.SENSITIVE_DATA),
                new ScanFinding(ScanFinding.Level.LOW, "heuristic", "y", "pkg", 1, null)
                        .withEvidence(
                                ScanFinding.EvidenceSource.HEURISTIC,
                                ScanFinding.EvidenceTag.REMOTE_CONTROL),
                new ScanFinding(ScanFinding.Level.INFO, "other", "z", "pkg", 0, null));

        SecurityBaselineStore.Snapshot snapshot =
                SecurityBaselineStore.fromFindings(findings);

        EnumSet<ScanFinding.EvidenceTag> tags = snapshot.byPackage.get("pkg");
        assertNotNull(tags);
        assertTrue(tags.contains(ScanFinding.EvidenceTag.ACTIVE_ACCESS));
        assertTrue(tags.contains(ScanFinding.EvidenceTag.SENSITIVE_DATA));
        assertFalse(tags.contains(ScanFinding.EvidenceTag.REMOTE_CONTROL));
    }

    @Test
    public void encodeDecodeRoundTripPreservesTrackedTags() {
        Map<String, EnumSet<ScanFinding.EvidenceTag>> map = new HashMap<>();
        map.put("com.example.app", EnumSet.of(
                ScanFinding.EvidenceTag.ACTIVE_ACCESS,
                ScanFinding.EvidenceTag.PERSISTENCE));

        SecurityBaselineStore.Snapshot decoded = SecurityBaselineStore.decode(
                SecurityBaselineStore.encode(new SecurityBaselineStore.Snapshot(map)));

        assertEquals(1, decoded.byPackage.size());
        assertTrue(decoded.byPackage.get("com.example.app")
                .contains(ScanFinding.EvidenceTag.ACTIVE_ACCESS));
        assertTrue(decoded.byPackage.get("com.example.app")
                .contains(ScanFinding.EvidenceTag.PERSISTENCE));
    }

    @Test
    public void newObservedPrivilegesCreateSingleDerivedChangeFinding() {
        Map<String, EnumSet<ScanFinding.EvidenceTag>> before = new HashMap<>();
        before.put("pkg", EnumSet.of(ScanFinding.EvidenceTag.SENSITIVE_DATA));

        Map<String, EnumSet<ScanFinding.EvidenceTag>> after = new HashMap<>();
        after.put("pkg", EnumSet.of(
                ScanFinding.EvidenceTag.SENSITIVE_DATA,
                ScanFinding.EvidenceTag.ACTIVE_ACCESS,
                ScanFinding.EvidenceTag.INSTALL_TRUST));

        List<ScanFinding> changes = SecurityBaselineStore.compare(
                new SecurityBaselineStore.Snapshot(before),
                new SecurityBaselineStore.Snapshot(after));

        assertEquals(1, changes.size());
        ScanFinding change = changes.get(0);
        assertEquals(ScanFinding.Level.MEDIUM, change.level);
        assertEquals(4, change.points);
        assertEquals(ScanFinding.EvidenceSource.DERIVED, change.evidenceSource);
        assertTrue(change.hasEvidenceTag(ScanFinding.EvidenceTag.CORRELATION));
        assertTrue(change.detail.contains("ACTIVE_ACCESS"));
        assertTrue(change.detail.contains("INSTALL_TRUST"));
    }

    @Test
    public void unchangedBaselineProducesNoChangeFinding() {
        Map<String, EnumSet<ScanFinding.EvidenceTag>> map = new HashMap<>();
        map.put("pkg", EnumSet.of(ScanFinding.EvidenceTag.ACTIVE_ACCESS));

        SecurityBaselineStore.Snapshot snapshot =
                new SecurityBaselineStore.Snapshot(map);

        assertTrue(SecurityBaselineStore.compare(snapshot, snapshot).isEmpty());
    }
}
