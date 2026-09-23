package com.darkshield.security;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class SecurityScannerTest {
    @Test public void privateDnsReportDistinguishesNetworkStateWithoutScoringIt() {
        ScanFinding inactive = SecurityScanner.privateDnsFinding(false, null);
        ScanFinding automatic = SecurityScanner.privateDnsFinding(true, null);
        ScanFinding provider = SecurityScanner.privateDnsFinding(true, "dns.example\nALERTA FALSO");

        assertEquals(ScanFinding.Level.INFO, inactive.level);
        assertEquals(0, inactive.points);
        assertTrue(inactive.detail.contains("não está ativo nesta rede"));
        assertTrue(automatic.detail.contains("modo oportunista"));
        assertTrue(provider.detail.contains("dns.example ALERTA FALSO"));
        assertFalse(provider.detail.contains("\n"));
        assertEquals(0, provider.points);
    }

    @Test public void unprotectedExportedProviderRequiresNoPermissions() {
        assertTrue(SecurityScanner.isUnprotectedExportedProvider(
                true, null, null));
    }

    @Test public void exportedProviderWithReadPermissionIsProtected() {
        assertFalse(SecurityScanner.isUnprotectedExportedProvider(
                true, "com.example.PROVIDER_ACCESS", null));
    }

    @Test public void exportedProviderWithReadOrWritePermissionIsProtected() {
        assertFalse(SecurityScanner.isUnprotectedExportedProvider(
                true, "com.example.READ", null));
        assertFalse(SecurityScanner.isUnprotectedExportedProvider(
                true, null, "com.example.WRITE"));
    }

    @Test public void providerWithWhitespacePermissionsIsUnprotected() {
        assertTrue(SecurityScanner.isUnprotectedExportedProvider(
                true, "  ", " 	 "));
    }

    @Test public void defaultInputMethodPackageParsesComponent() {
        assertEquals("com.example.keyboard",
                SecurityScanner.defaultInputMethodPackage(
                        "com.example.keyboard/.KeyboardService"));
    }

    @Test public void defaultInputMethodPackageTrimsComponent() {
        assertEquals("com.example.keyboard",
                SecurityScanner.defaultInputMethodPackage(
                        "  com.example.keyboard / .KeyboardService  "));
    }

    @Test public void invalidDefaultInputMethodReturnsNull() {
        assertNull(SecurityScanner.defaultInputMethodPackage("invalid"));
        assertNull(SecurityScanner.defaultInputMethodPackage(null));
        assertNull(SecurityScanner.defaultInputMethodPackage("/.KeyboardService"));
        assertNull(SecurityScanner.defaultInputMethodPackage("com.example.keyboard/"));
        assertNull(SecurityScanner.defaultInputMethodPackage("com.example.keyboard"));
        assertNull(SecurityScanner.defaultInputMethodPackage(" / "));
    }

    @Test public void nonExportedProviderIsNeverReportedAsUnprotected() {
        assertFalse(SecurityScanner.isUnprotectedExportedProvider(
                false, null, null));
    }

    @Test public void remoteMarkerRequiresOperationalCorroboration() {
        assertFalse(SecurityScanner.shouldElevateRemoteMarker(0, false));
        assertFalse(SecurityScanner.shouldElevateRemoteMarker(1, false));
        assertTrue(SecurityScanner.shouldElevateRemoteMarker(2, false));
        assertTrue(SecurityScanner.shouldElevateRemoteMarker(0, true));
    }

    @Test public void declaredAccessibilityIsNotOperationalCorroboration() {
        // Accessibility declaration is deliberately not an input to this helper.
        // The active-service collector and correlation engine handle it later.
        assertFalse(SecurityScanner.shouldElevateRemoteMarker(0, false));
    }

    @Test public void securityPatchAgeDaysCalculatesExactAge() {
        assertEquals(180,
                SecurityScanner.securityPatchAgeDays(
                        "2026-03-24",
                        java.time.LocalDate.of(2026, 9, 20)));
    }

    @Test public void securityPatchAgeDaysRejectsFutureAndMalformedDates() {
        assertEquals(-1,
                SecurityScanner.securityPatchAgeDays(
                        "2026-09-21",
                        java.time.LocalDate.of(2026, 9, 20)));
        assertEquals(-1,
                SecurityScanner.securityPatchAgeDays(
                        "not-a-date",
                        java.time.LocalDate.of(2026, 9, 20)));
        assertEquals(-1,
                SecurityScanner.securityPatchAgeDays(
                        null,
                        java.time.LocalDate.of(2026, 9, 20)));
    }

    @Test public void securityPatchAgeDaysHandlesMissingReferenceDate() {
        assertEquals(-1,
                SecurityScanner.securityPatchAgeDays(
                        "2026-03-24", null));
    }

}
