package com.darkshield.security;

import android.content.pm.ProviderInfo;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SecurityScannerTest {
    @Test public void unprotectedExportedProviderRequiresNoPermissions() {
        ProviderInfo provider = new ProviderInfo();
        provider.exported = true;
        assertTrue(SecurityScanner.isUnprotectedExportedProvider(provider));
    }

    @Test public void exportedProviderWithReadPermissionIsProtected() {
        ProviderInfo provider = new ProviderInfo();
        provider.exported = true;
        provider.readPermission = "com.example.PROVIDER_ACCESS";
        assertFalse(SecurityScanner.isUnprotectedExportedProvider(provider));
    }

    @Test public void exportedProviderWithReadOrWritePermissionIsProtected() {
        ProviderInfo readProtected = new ProviderInfo();
        readProtected.exported = true;
        readProtected.readPermission = "com.example.READ";
        assertFalse(SecurityScanner.isUnprotectedExportedProvider(readProtected));

        ProviderInfo writeProtected = new ProviderInfo();
        writeProtected.exported = true;
        writeProtected.writePermission = "com.example.WRITE";
        assertFalse(SecurityScanner.isUnprotectedExportedProvider(writeProtected));
    }

    @Test public void nonExportedProviderIsNeverReportedAsUnprotected() {
        ProviderInfo provider = new ProviderInfo();
        provider.exported = false;
        assertFalse(SecurityScanner.isUnprotectedExportedProvider(provider));
    }
}
