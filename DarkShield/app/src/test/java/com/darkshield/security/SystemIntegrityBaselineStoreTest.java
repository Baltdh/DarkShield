package com.darkshield.security;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class SystemIntegrityBaselineStoreTest {
    private static SystemIntegrityBaselineStore.Snapshot snapshot(
            String root, String testKeys, String debuggable, String manager) {
        Map<String, String> values = new HashMap<>();
        values.put(SystemIntegrityBaselineStore.ATTR_ROOT_BINARY, root);
        values.put(SystemIntegrityBaselineStore.ATTR_TEST_KEYS, testKeys);
        values.put(SystemIntegrityBaselineStore.ATTR_DEBUGGABLE_BUILD, debuggable);
        values.put(SystemIntegrityBaselineStore.ATTR_ROOT_MANAGER, manager);
        return new SystemIntegrityBaselineStore.Snapshot(values);
    }

    @Test
    public void newRootBinaryIsHighSeverityChange() {
        List<ScanFinding> findings = SystemIntegrityBaselineStore.compare(
                snapshot("0", "0", "0", "0"),
                snapshot("1", "0", "0", "0"));

        assertEquals(1, findings.size());
        assertEquals(ScanFinding.Level.HIGH, findings.get(0).level);
        assertEquals(
                "1",
                findings.get(0).attribute(
                        SystemIntegrityBaselineStore.ATTR_CHANGE_ROOT_BINARY));
    }

    @Test
    public void newRootManagerMarkerIsMediumChange() {
        List<ScanFinding> findings = SystemIntegrityBaselineStore.compare(
                snapshot("0", "0", "0", "0"),
                snapshot("0", "0", "0", "1"));

        assertEquals(1, findings.size());
        assertEquals(ScanFinding.Level.MEDIUM, findings.get(0).level);
        assertEquals(
                "1",
                findings.get(0).attribute(
                        SystemIntegrityBaselineStore.ATTR_CHANGE_ROOT_MANAGER));
    }

    @Test
    public void unchangedIntegrityProducesNoChangeFinding() {
        SystemIntegrityBaselineStore.Snapshot state =
                snapshot("0", "0", "0", "0");
        assertTrue(SystemIntegrityBaselineStore.compare(state, state).isEmpty());
    }

    @Test
    public void disappearingRootIndicatorIsNotReportedAsCompromise() {
        assertTrue(SystemIntegrityBaselineStore.compare(
                snapshot("1", "0", "0", "1"),
                snapshot("0", "0", "0", "0")).isEmpty());
    }

    @Test
    public void structuredFindingBuildsSnapshot() {
        ScanFinding finding = new ScanFinding(
                ScanFinding.Level.INFO,
                "Estado técnico de integridade",
                "x",
                null,
                0,
                null)
                .withAttribute(SystemIntegrityBaselineStore.ATTR_ROOT_BINARY, "1")
                .withAttribute(SystemIntegrityBaselineStore.ATTR_TEST_KEYS, "0")
                .withAttribute(SystemIntegrityBaselineStore.ATTR_DEBUGGABLE_BUILD, "0")
                .withAttribute(SystemIntegrityBaselineStore.ATTR_ROOT_MANAGER, "1");

        SystemIntegrityBaselineStore.Snapshot snapshot =
                SystemIntegrityBaselineStore.fromFindings(
                        Arrays.asList(finding));

        assertEquals("1", snapshot.get(SystemIntegrityBaselineStore.ATTR_ROOT_BINARY));
        assertEquals("1", snapshot.get(SystemIntegrityBaselineStore.ATTR_ROOT_MANAGER));
    }

    @Test
    public void encodeDecodeRoundTripPreservesState() {
        SystemIntegrityBaselineStore.Snapshot decoded =
                SystemIntegrityBaselineStore.decode(
                        SystemIntegrityBaselineStore.encode(
                                snapshot("1", "0", "1", "0")));

        assertEquals("1", decoded.get(SystemIntegrityBaselineStore.ATTR_ROOT_BINARY));
        assertEquals("1", decoded.get(SystemIntegrityBaselineStore.ATTR_DEBUGGABLE_BUILD));
    }
}
