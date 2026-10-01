package com.darkshield.security.analysis;

import org.junit.Test;
import static org.junit.Assert.*;

public class SystemAppIdentityHeuristicsTest {
    @Test public void detectsGenericSystemImpersonationNames() {
        assertTrue(SystemAppIdentityHeuristics.claimsSystemIdentity(
                "System Update", "com.example.updater", "motorola", "motorola"));
        assertTrue(SystemAppIdentityHeuristics.claimsSystemIdentity(
                "Weather", "com.android.securitycenter", "motorola", "motorola"));
        assertTrue(SystemAppIdentityHeuristics.claimsSystemIdentity(
                "Play helper", "com.google.android.security", "motorola", "motorola"));
    }

    @Test public void detectsCurrentOemImpersonationWithoutHardcodingOneVendor() {
        assertTrue(SystemAppIdentityHeuristics.claimsSystemIdentity(
                "Motorola Security", "evil.app", "motorola", "motorola"));
        assertTrue(SystemAppIdentityHeuristics.claimsSystemIdentity(
                "Updater", "com.samsung.fake", "samsung", "samsung"));
    }

    @Test public void ordinaryThirdPartyNamesAreNotClaims() {
        assertFalse(SystemAppIdentityHeuristics.claimsSystemIdentity(
                "Banco Exemplo", "br.com.example.bank", "motorola", "motorola"));
        assertFalse(SystemAppIdentityHeuristics.claimsSystemIdentity(
                "Photo Editor", "com.example.photo", "samsung", "samsung"));
    }

    @Test public void systemFlagSuppressesImpersonationRisk() {
        assertEquals(0, SystemAppIdentityHeuristics.impersonationRisk(
                true, true, false, 5, true, true, true));
    }

    @Test public void nameClaimAloneStaysWeak() {
        assertEquals(2, SystemAppIdentityHeuristics.impersonationRisk(
                false, true, true, 0, false, false, false));
    }

    @Test public void contradictoryCapabilitiesRaiseRisk() {
        assertEquals(10, SystemAppIdentityHeuristics.impersonationRisk(
                false, true, false, 3, true, true, true));
        assertEquals(7, SystemAppIdentityHeuristics.impersonationRisk(
                false, true, false, 1, true, false, false));
    }
}
