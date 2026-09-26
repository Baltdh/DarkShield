package com.darkshield.security;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;

public class PackageIdentityBaselineStoreTest {
    private static Set<String> set(String... values) {
        return new LinkedHashSet<>(Arrays.asList(values));
    }

    private static PackageIdentityBaselineStore.Identity identity(
            String pkg,
            long version,
            String installer,
            long firstInstall,
            String currentSigner,
            String... lineage) {
        return new PackageIdentityBaselineStore.Identity(
                pkg,
                version,
                installer,
                firstInstall,
                firstInstall + 1000L,
                currentSigner == null ? Collections.emptySet() : set(currentSigner),
                set(lineage));
    }

    private static PackageIdentityBaselineStore.Snapshot snapshot(
            PackageIdentityBaselineStore.Identity identity) {
        Map<String, PackageIdentityBaselineStore.Identity> map = new HashMap<>();
        map.put(identity.packageName, identity);
        return new PackageIdentityBaselineStore.Snapshot(map);
    }

    @Test
    public void signingRotationWithPreviousCertificateInLineageIsRiskNeutral() {
        PackageIdentityBaselineStore.Identity before =
                identity("pkg", 10, "store", 1000L, "AAA", "AAA");
        PackageIdentityBaselineStore.Identity after =
                identity("pkg", 11, "store", 1000L, "BBB", "AAA", "BBB");

        List<ScanFinding> findings = PackageIdentityBaselineStore.compare(
                snapshot(before), snapshot(after));

        assertEquals(1, findings.size());
        ScanFinding finding = findings.get(0);
        assertEquals(ScanFinding.Level.INFO, finding.level);
        assertEquals(0, finding.points);
        assertTrue(finding.title.contains("Rotação"));
        assertFalse(finding.hasEvidenceTag(ScanFinding.EvidenceTag.CORRELATION));
    }

    @Test
    public void unrelatedSignerChangeIsHighRiskInstallTrustFinding() {
        PackageIdentityBaselineStore.Identity before =
                identity("pkg", 10, "store", 1000L, "AAA", "AAA");
        PackageIdentityBaselineStore.Identity after =
                identity("pkg", 11, "store", 1000L, "BBB", "BBB");

        List<ScanFinding> findings = PackageIdentityBaselineStore.compare(
                snapshot(before), snapshot(after));

        assertEquals(1, findings.size());
        ScanFinding finding = findings.get(0);
        assertEquals(ScanFinding.Level.HIGH, finding.level);
        assertEquals(7, finding.points);
        assertTrue(finding.hasEvidenceTag(ScanFinding.EvidenceTag.INSTALL_TRUST));
        assertTrue(finding.hasEvidenceTag(ScanFinding.EvidenceTag.CORRELATION));
    }

    @Test
    public void downgradeIsDetectedWithoutSignerChange() {
        PackageIdentityBaselineStore.Identity before =
                identity("pkg", 20, "store", 1000L, "AAA", "AAA");
        PackageIdentityBaselineStore.Identity after =
                identity("pkg", 19, "store", 1000L, "AAA", "AAA");

        List<ScanFinding> findings = PackageIdentityBaselineStore.compare(
                snapshot(before), snapshot(after));

        assertEquals(1, findings.size());
        assertEquals(ScanFinding.Level.MEDIUM, findings.get(0).level);
        assertTrue(findings.get(0).detail.contains("VersionCode reduziu"));
    }

    @Test
    public void reinstallAndInstallerChangeAreReported() {
        PackageIdentityBaselineStore.Identity before =
                identity("pkg", 10, "store.one", 1000L, "AAA", "AAA");
        PackageIdentityBaselineStore.Identity after =
                identity("pkg", 10, "store.two", 2000L, "AAA", "AAA");

        List<ScanFinding> findings = PackageIdentityBaselineStore.compare(
                snapshot(before), snapshot(after));

        assertEquals(1, findings.size());
        assertTrue(findings.get(0).detail.contains("Instalador mudou"));
        assertTrue(findings.get(0).detail.contains("primeira instalação mudou"));
    }

    @Test
    public void encodeDecodeRoundTripPreservesIdentity() {
        PackageIdentityBaselineStore.Identity identity =
                identity("com.example.app", 42, "store", 1234L, "AAA", "AAA", "BBB");

        PackageIdentityBaselineStore.Snapshot decoded =
                PackageIdentityBaselineStore.decode(
                        PackageIdentityBaselineStore.encode(snapshot(identity)));

        PackageIdentityBaselineStore.Identity restored =
                decoded.byPackage.get("com.example.app");
        assertNotNull(restored);
        assertEquals(42L, restored.versionCode);
        assertEquals("store", restored.installer);
        assertTrue(restored.currentSigners.contains("AAA"));
        assertTrue(restored.signingLineage.contains("BBB"));
    }

    @Test
    public void structuredFindingBuildsIdentitySnapshot() {
        Map<String, String> attrs = new HashMap<>();
        attrs.put(PackageIdentityBaselineStore.ATTR_VERSION_CODE, "9");
        attrs.put(PackageIdentityBaselineStore.ATTR_INSTALLER, "store");
        attrs.put(PackageIdentityBaselineStore.ATTR_FIRST_INSTALL, "100");
        attrs.put(PackageIdentityBaselineStore.ATTR_LAST_UPDATE, "200");
        attrs.put(PackageIdentityBaselineStore.ATTR_CURRENT_SIGNERS, "AAA");
        attrs.put(PackageIdentityBaselineStore.ATTR_SIGNING_LINEAGE, "AAA,BBB");

        ScanFinding finding = new ScanFinding(
                ScanFinding.Level.INFO,
                "Identidade técnica do pacote",
                "x",
                "pkg",
                0,
                null).withAttributes(attrs);

        PackageIdentityBaselineStore.Snapshot snapshot =
                PackageIdentityBaselineStore.fromFindings(
                        Collections.singletonList(finding));

        assertEquals(1, snapshot.byPackage.size());
        assertEquals(9L, snapshot.byPackage.get("pkg").versionCode);
    }
}
