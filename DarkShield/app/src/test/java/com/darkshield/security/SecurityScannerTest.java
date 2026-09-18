package com.darkshield.security;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SecurityScannerTest {
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

     @Test public void nonExportedProviderIsNeverReportedAsUnprotected() {
        assertFalse(SecurityScanner.isUnprotectedExportedProvider(
                false, null, null));
    }
}
