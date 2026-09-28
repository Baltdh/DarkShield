package com.darkshield.security.analysis;

import org.junit.Test;
import static org.junit.Assert.*;

public class PackageIdentityBaselineTest {
    @Test public void unchangedSignerIsIgnored() {
        assertEquals(
                PackageIdentityBaseline.SignerChange.NONE,
                PackageIdentityBaseline.compareSigner("AA", "aa", false));
    }

    @Test public void signingRotationIsDistinguishedFromReplacement() {
        assertEquals(
                PackageIdentityBaseline.SignerChange.LEGITIMATE_ROTATION,
                PackageIdentityBaseline.compareSigner("OLD", "NEW", true));
        assertEquals(
                PackageIdentityBaseline.SignerChange.UNEXPECTED_CHANGE,
                PackageIdentityBaseline.compareSigner("OLD", "NEW", false));
    }

    @Test public void detectsVersionDowngradeOnlyWhenBothVersionsKnown() {
        assertTrue(PackageIdentityBaseline.isDowngrade(20L, 19L));
        assertFalse(PackageIdentityBaseline.isDowngrade(20L, 20L));
        assertFalse(PackageIdentityBaseline.isDowngrade(20L, 21L));
        assertFalse(PackageIdentityBaseline.isDowngrade(-1L, 1L));
    }

    @Test public void installerChangeRequiresTwoKnownSources() {
        assertTrue(PackageIdentityBaseline.installerChanged(
                "com.android.vending", "com.example.store"));
        assertFalse(PackageIdentityBaseline.installerChanged(
                "com.android.vending", "COM.ANDROID.VENDING"));
        assertFalse(PackageIdentityBaseline.installerChanged(
                null, "com.android.vending"));
        assertFalse(PackageIdentityBaseline.installerChanged(
                "com.android.vending", null));
    }
    @Test public void suspiciousIdentityStateDoesNotReplaceTrustedBaseline() {
        assertFalse(PackageIdentityBaseline.shouldUpdateSignerBaseline(
                "OLD", "NEW", false));
        assertFalse(PackageIdentityBaseline.shouldUpdateVersionBaseline(
                20L, 19L));
        assertFalse(PackageIdentityBaseline.shouldUpdateInstallerBaseline(
                "com.android.vending", "com.example.store"));
    }

    @Test public void legitimateIdentityEvolutionCanAdvanceBaseline() {
        assertTrue(PackageIdentityBaseline.shouldUpdateSignerBaseline(
                "OLD", "NEW", true));
        assertTrue(PackageIdentityBaseline.shouldUpdateVersionBaseline(
                20L, 21L));
        assertTrue(PackageIdentityBaseline.shouldUpdateInstallerBaseline(
                null, "com.android.vending"));
    }

}
