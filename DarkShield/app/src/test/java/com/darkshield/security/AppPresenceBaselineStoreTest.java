package com.darkshield.security;

import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class AppPresenceBaselineStoreTest {
    private static PackageIdentityBaselineStore.Identity identity(
            String pkg,
            long version,
            String installer,
            String currentSigner,
            String... lineage) {
        java.util.Set<String> current = new LinkedHashSet<>();
        if (currentSigner != null) current.add(currentSigner);
        java.util.Set<String> history = new LinkedHashSet<>();
        if (lineage != null) Collections.addAll(history, lineage);
        return new PackageIdentityBaselineStore.Identity(
                pkg,
                version,
                installer,
                100L,
                200L,
                current,
                history);
    }

    private static PackageIdentityBaselineStore.Snapshot current(
            PackageIdentityBaselineStore.Identity... identities) {
        Map<String, PackageIdentityBaselineStore.Identity> map = new HashMap<>();
        for (PackageIdentityBaselineStore.Identity identity : identities) {
            map.put(identity.packageName, identity);
        }
        return new PackageIdentityBaselineStore.Snapshot(map);
    }

    @Test
    public void firstSnapshotDoesNotCreateReappearanceFinding() {
        AppPresenceBaselineStore.Snapshot initialized =
                AppPresenceBaselineStore.initialize(
                        current(identity("pkg", 10, "store", "AAA", "AAA")));

        assertEquals(1, initialized.states.size());
        assertFalse(initialized.states.get("pkg").missingAfterSeen);
    }

    @Test
    public void missingThenReturningPackageCreatesFinding() {
        AppPresenceBaselineStore.Snapshot initial =
                AppPresenceBaselineStore.initialize(
                        current(identity("pkg", 10, "store", "AAA", "AAA")));

        AppPresenceBaselineStore.UpdateResult missing =
                AppPresenceBaselineStore.update(
                        initial,
                        current());
        assertTrue(missing.findings.isEmpty());
        assertTrue(missing.next.states.get("pkg").missingAfterSeen);

        AppPresenceBaselineStore.UpdateResult returned =
                AppPresenceBaselineStore.update(
                        missing.next,
                        current(identity("pkg", 10, "store", "AAA", "AAA")));

        assertEquals(1, returned.findings.size());
        assertEquals(ScanFinding.Level.LOW, returned.findings.get(0).level);
        assertEquals(
                "1",
                returned.findings.get(0).attribute(
                        AppPresenceBaselineStore.ATTR_CHANGE_REAPPEARED));
        assertFalse(returned.next.states.get("pkg").missingAfterSeen);
    }

    @Test
    public void reappearanceWithUnrelatedSignerIsHighSeverity() {
        AppPresenceBaselineStore.State old = new AppPresenceBaselineStore.State(
                "pkg",
                true,
                10,
                "store",
                new LinkedHashSet<>(Collections.singletonList("AAA")));

        ScanFinding finding = AppPresenceBaselineStore.reappearanceFinding(
                old,
                identity("pkg", 11, "store", "BBB", "BBB"));

        assertEquals(ScanFinding.Level.HIGH, finding.level);
        assertEquals(
                "1",
                finding.attribute(
                        AppPresenceBaselineStore.ATTR_REAPPEAR_SIGNER_MISMATCH));
        assertTrue(finding.hasEvidenceTag(ScanFinding.EvidenceTag.INSTALL_TRUST));
    }

    @Test
    public void reappearanceWithSigningLineageIsNotSignerMismatch() {
        AppPresenceBaselineStore.State old = new AppPresenceBaselineStore.State(
                "pkg",
                true,
                10,
                "store",
                new LinkedHashSet<>(Collections.singletonList("AAA")));

        ScanFinding finding = AppPresenceBaselineStore.reappearanceFinding(
                old,
                identity("pkg", 11, "store", "BBB", "AAA", "BBB"));

        assertEquals(ScanFinding.Level.LOW, finding.level);
        assertEquals(
                "1",
                finding.attribute(
                        AppPresenceBaselineStore.ATTR_REAPPEAR_SIGNER_ROTATION));
        assertNull(finding.attribute(
                AppPresenceBaselineStore.ATTR_REAPPEAR_SIGNER_MISMATCH));
    }

    @Test
    public void reappearanceWithDowngradeIsMediumSeverity() {
        AppPresenceBaselineStore.State old = new AppPresenceBaselineStore.State(
                "pkg",
                true,
                20,
                "store",
                new LinkedHashSet<>(Collections.singletonList("AAA")));

        ScanFinding finding = AppPresenceBaselineStore.reappearanceFinding(
                old,
                identity("pkg", 19, "store", "AAA", "AAA"));

        assertEquals(ScanFinding.Level.MEDIUM, finding.level);
        assertEquals(
                "1",
                finding.attribute(
                        AppPresenceBaselineStore.ATTR_REAPPEAR_DOWNGRADE));
    }

    @Test
    public void encodeDecodeRoundTripPreservesMissingState() {
        Map<String, AppPresenceBaselineStore.State> map = new HashMap<>();
        map.put(
                "com.example",
                new AppPresenceBaselineStore.State(
                        "com.example",
                        true,
                        42,
                        "store",
                        new LinkedHashSet<>(Collections.singletonList("AAA"))));

        AppPresenceBaselineStore.Snapshot decoded =
                AppPresenceBaselineStore.decode(
                        AppPresenceBaselineStore.encode(
                                new AppPresenceBaselineStore.Snapshot(map)));

        assertEquals(1, decoded.states.size());
        assertTrue(decoded.states.get("com.example").missingAfterSeen);
        assertEquals(42L, decoded.states.get("com.example").versionCode);
        assertTrue(decoded.states.get("com.example").currentSigners.contains("AAA"));
    }
    @Test
    public void consecutiveMissingScansAreCounted() {
        AppPresenceBaselineStore.Snapshot initial =
                AppPresenceBaselineStore.initialize(
                        current(identity("pkg", 10, "store", "AAA", "AAA")));

        AppPresenceBaselineStore.UpdateResult firstMissing =
                AppPresenceBaselineStore.update(initial, current());
        AppPresenceBaselineStore.UpdateResult secondMissing =
                AppPresenceBaselineStore.update(firstMissing.next, current());

        assertEquals(2, secondMissing.next.states.get("pkg").missingScanCount);

        AppPresenceBaselineStore.UpdateResult returned =
                AppPresenceBaselineStore.update(
                        secondMissing.next,
                        current(identity("pkg", 10, "store", "AAA", "AAA")));

        assertEquals(1, returned.findings.size());
        assertTrue(returned.findings.get(0).detail.contains("2 verificação"));
    }

    @Test
    public void decoderAcceptsLegacyFiveFieldPresenceState() {
        AppPresenceBaselineStore.Snapshot current =
                AppPresenceBaselineStore.initialize(
                        current(identity("pkg", 10, "store", "AAA", "AAA")));
        String encoded = AppPresenceBaselineStore.encode(current);
        String[] fields = encoded.split("\\t", -1);

        String legacy = fields[0] + "\t" + fields[1] + "\t"
                + fields[3] + "\t" + fields[4] + "\t" + fields[5];

        AppPresenceBaselineStore.Snapshot decoded =
                AppPresenceBaselineStore.decode(legacy);

        assertEquals(1, decoded.states.size());
        assertEquals(10L, decoded.states.get("pkg").versionCode);
    }

}
