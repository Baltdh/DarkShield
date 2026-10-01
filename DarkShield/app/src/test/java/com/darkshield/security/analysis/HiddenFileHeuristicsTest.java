package com.darkshield.security.analysis;

import org.junit.Test;
import java.io.File;
import static org.junit.Assert.*;

public class HiddenFileHeuristicsTest {
    @Test public void dotFilesAreRecognizedAsHidden() {
        assertTrue(HiddenFileHeuristics.isHiddenName(".payload.apk"));
        assertFalse(HiddenFileHeuristics.isHiddenName("payload.apk"));
        assertFalse(HiddenFileHeuristics.isHiddenName("."));
    }

    @Test public void executablePayloadExtensionsAreRecognized() {
        assertTrue(HiddenFileHeuristics.hasExecutablePayloadExtension("module.dex"));
        assertTrue(HiddenFileHeuristics.hasExecutablePayloadExtension("update.APK"));
        assertTrue(HiddenFileHeuristics.hasExecutablePayloadExtension("libstage.so"));
        assertFalse(HiddenFileHeuristics.hasExecutablePayloadExtension("photo.jpg"));
    }

    @Test public void doubleExtensionsAreTreatedAsDisguisedPayloads() {
        assertTrue(HiddenFileHeuristics.looksLikeDisguisedPayload("invoice.pdf.apk"));
        assertTrue(HiddenFileHeuristics.looksLikeDisguisedPayload("payload.dex.jpg"));
        assertFalse(HiddenFileHeuristics.looksLikeDisguisedPayload("normal.apk"));
    }

    @Test public void detectsDexAndElfMagicRegardlessOfFilename() {
        assertEquals(
                HiddenFileHeuristics.ExecutableMagic.DEX,
                HiddenFileHeuristics.detectExecutableMagic(
                        new byte[]{'d','e','x','\n'}));
        assertEquals(
                HiddenFileHeuristics.ExecutableMagic.ELF,
                HiddenFileHeuristics.detectExecutableMagic(
                        new byte[]{0x7F,'E','L','F'}));
    }

    @Test public void disguisedExecutableMagicGetsHigherRisk() {
        assertEquals(5, HiddenFileHeuristics.magicRisk(
                "photo.jpg", new byte[]{0x7F,'E','L','F'}));
        assertEquals(5, HiddenFileHeuristics.magicRisk(
                "notes.txt", new byte[]{'d','e','x','\n'}));
        assertEquals(2, HiddenFileHeuristics.magicRisk(
                "classes.dex", new byte[]{'d','e','x','\n'}));
    }


    @Test public void normalDocumentsStayBelowReportingThreshold() {
        File normal = new File("notes.txt");
        assertFalse(HiddenFileHeuristics.shouldReport(normal, true));
    }

    @Test public void hiddenSharedPayloadReachesReportingThreshold() {
        File hidden = new File(".stage.dex");
        assertTrue(HiddenFileHeuristics.shouldReport(hidden, true));
        assertTrue(HiddenFileHeuristics.riskScore(hidden, true) >= 4);
    }
}
