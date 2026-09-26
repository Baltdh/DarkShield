package com.darkshield.security;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class DevicePostureBaselineStoreTest {
    private static DevicePostureBaselineStore.Snapshot snapshot(
            String dev,
            String adb,
            String patch,
            String ime,
            String sms,
            String dialer) {
        Map<String, String> values = new HashMap<>();
        values.put(DevicePostureBaselineStore.ATTR_DEV_OPTIONS, dev);
        values.put(DevicePostureBaselineStore.ATTR_ADB, adb);
        values.put(DevicePostureBaselineStore.ATTR_SECURITY_PATCH, patch);
        values.put(DevicePostureBaselineStore.ATTR_DEFAULT_IME, ime);
        values.put(DevicePostureBaselineStore.ATTR_DEFAULT_SMS, sms);
        values.put(DevicePostureBaselineStore.ATTR_DEFAULT_DIALER, dialer);
        return new DevicePostureBaselineStore.Snapshot(values);
    }

    @Test
    public void newlyEnabledAdbProducesSingleMediumFinding() {
        DevicePostureBaselineStore.Snapshot before =
                snapshot("0", "0", "2026-09-05", "ime", "sms", "dialer");
        DevicePostureBaselineStore.Snapshot after =
                snapshot("1", "1", "2026-09-05", "ime", "sms", "dialer");

        List<ScanFinding> findings =
                DevicePostureBaselineStore.compare(before, after);

        assertEquals(1, findings.size());
        assertEquals(ScanFinding.Level.MEDIUM, findings.get(0).level);
        assertEquals(4, findings.get(0).points);
        assertTrue(findings.get(0).title.contains("ADB"));
    }

    @Test
    public void patchRegressionIsHighSeverity() {
        DevicePostureBaselineStore.Snapshot before =
                snapshot("0", "0", "2026-09-05", "ime", "sms", "dialer");
        DevicePostureBaselineStore.Snapshot after =
                snapshot("0", "0", "2026-08-05", "ime", "sms", "dialer");

        List<ScanFinding> findings =
                DevicePostureBaselineStore.compare(before, after);

        assertEquals(1, findings.size());
        assertEquals(ScanFinding.Level.HIGH, findings.get(0).level);
        assertTrue(findings.get(0).hasEvidenceTag(
                ScanFinding.EvidenceTag.VULNERABILITY));
    }

    @Test
    public void keyboardChangeIsAssociatedWithNewPackage() {
        DevicePostureBaselineStore.Snapshot before =
                snapshot("0", "0", "2026-09-05", "ime.old", "sms", "dialer");
        DevicePostureBaselineStore.Snapshot after =
                snapshot("0", "0", "2026-09-05", "ime.new", "sms", "dialer");

        List<ScanFinding> findings =
                DevicePostureBaselineStore.compare(before, after);

        assertEquals(1, findings.size());
        assertEquals("ime.new", findings.get(0).packageName);
        assertEquals(ScanFinding.Level.MEDIUM, findings.get(0).level);
    }

    @Test
    public void identicalPostureProducesNoFindings() {
        DevicePostureBaselineStore.Snapshot state =
                snapshot("0", "0", "2026-09-05", "ime", "sms", "dialer");

        assertTrue(DevicePostureBaselineStore.compare(state, state).isEmpty());
    }

    @Test
    public void patchRegressionIgnoresMalformedDates() {
        assertFalse(DevicePostureBaselineStore.patchRegressed(
                "bad", "2026-09-05"));
        assertFalse(DevicePostureBaselineStore.patchRegressed(
                "2026-09-05", "bad"));
    }

    @Test
    public void structuredAttributesBuildSnapshot() {
        ScanFinding dev = new ScanFinding(
                ScanFinding.Level.INFO, "Dev", "x", null, 0, null)
                .withAttribute(DevicePostureBaselineStore.ATTR_DEV_OPTIONS, "1");
        ScanFinding adb = new ScanFinding(
                ScanFinding.Level.MEDIUM, "ADB", "x", null, 4, null)
                .withAttribute(DevicePostureBaselineStore.ATTR_ADB, "1");

        DevicePostureBaselineStore.Snapshot snapshot =
                DevicePostureBaselineStore.fromFindings(Arrays.asList(dev, adb));

        assertEquals("1", snapshot.get(DevicePostureBaselineStore.ATTR_DEV_OPTIONS));
        assertEquals("1", snapshot.get(DevicePostureBaselineStore.ATTR_ADB));
    }
    @Test
    public void advancedProtectionDisableIsDetected() {
        Map<String, String> beforeValues = new HashMap<>();
        beforeValues.put(DevicePostureBaselineStore.ATTR_ADVANCED_PROTECTION, "1");
        Map<String, String> afterValues = new HashMap<>();
        afterValues.put(DevicePostureBaselineStore.ATTR_ADVANCED_PROTECTION, "0");

        List<ScanFinding> findings = DevicePostureBaselineStore.compare(
                new DevicePostureBaselineStore.Snapshot(beforeValues),
                new DevicePostureBaselineStore.Snapshot(afterValues));

        assertEquals(1, findings.size());
        assertEquals(ScanFinding.Level.MEDIUM, findings.get(0).level);
        assertEquals(
                "1",
                findings.get(0).attribute(
                        DevicePostureBaselineStore.ATTR_CHANGE_ADVANCED_PROTECTION_DISABLED));
    }

    @Test
    public void advancedProtectionEnableIsNotTreatedAsRegression() {
        Map<String, String> beforeValues = new HashMap<>();
        beforeValues.put(DevicePostureBaselineStore.ATTR_ADVANCED_PROTECTION, "0");
        Map<String, String> afterValues = new HashMap<>();
        afterValues.put(DevicePostureBaselineStore.ATTR_ADVANCED_PROTECTION, "1");

        assertTrue(DevicePostureBaselineStore.compare(
                new DevicePostureBaselineStore.Snapshot(beforeValues),
                new DevicePostureBaselineStore.Snapshot(afterValues)).isEmpty());
    }

}
