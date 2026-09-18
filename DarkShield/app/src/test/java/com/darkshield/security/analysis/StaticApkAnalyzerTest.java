package com.darkshield.security.analysis;

import com.darkshield.security.ScanFinding;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class StaticApkAnalyzerTest {

    @Test public void analyzesApkStructureAndHash() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "resources.arsc", new byte[]{1});
            add(zip, "classes.dex", new byte[]{1, 2, 3});
            add(zip, "lib/arm64-v8a/libdemo.so", new byte[]{4});
        }

        List<ScanFinding> findings = StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");
        assertTrue(findings.stream().anyMatch(x -> x.title.equals("Estrutura ZIP do APK")));
        assertTrue(findings.stream().anyMatch(x -> x.title.equals("SHA-256 do APK")));
        assertEquals(0, findings.stream().filter(x -> x.level == ScanFinding.Level.MEDIUM).count());

        assertTrue(apk.delete());
    }

    @Test public void suspiciousNamesAreOnlyHeuristic() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "lib/arm64-v8a/libfrida.so", new byte[]{1});
        }

        List<ScanFinding> findings = StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");
        ScanFinding hit = findings.stream()
                .filter(x -> x.title.contains("instrumentação"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.LOW, hit.level);
        assertTrue(hit.detail.contains("não prova comportamento malicioso"));

        assertTrue(apk.delete());
    }

    @Test public void suspiciousResourceMarkersAreInformationalOnly() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "assets/frida-agent.bin", new byte[]{1});
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");
        ScanFinding hit = findings.stream()
                .filter(x -> x.title.contains("recurso não executável"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.INFO, hit.level);
        assertEquals(0, hit.points);
        assertTrue(hit.detail.contains("não foi pontuado isoladamente"));

        assertTrue(apk.delete());
    }

    @Test public void suspiciousContentInsideDexIsDetected() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "classes.dex", "prefix-frida-server-suffix".getBytes("ISO-8859-1"));
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");
        ScanFinding hit = findings.stream()
                .filter(x -> x.title.contains("conteúdo de DEX"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.LOW, hit.level);
        assertTrue(hit.detail.contains("classes.dex:frida"));
        assertTrue(hit.detail.contains("amostra analisada de DEX/bibliotecas"));
        assertTrue(!hit.detail.contains("prefixo analisado"));

        assertTrue(apk.delete());
    }

    @Test public void staticContentMarkerRemainsLowSeverity() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "classes.dex", "library-name-frida-helper".getBytes("ISO-8859-1"));
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");

        ScanFinding hit = findings.stream()
                .filter(x -> x.title.contains("conteúdo de DEX"))
                .findFirst().orElse(null);
        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.LOW, hit.level);
        assertTrue(hit.points <= 2);

        assertTrue(apk.delete());
    }

    @Test public void suspiciousContentNearDexTailIsDetected() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        byte[] data = new byte[(2 * 1024 * 1024) + 256];
        byte[] marker = "tail-frida-marker".getBytes("ISO-8859-1");
        System.arraycopy(marker, 0, data, data.length - marker.length, marker.length);

        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "classes.dex", data);
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");
        ScanFinding hit = findings.stream()
                .filter(x -> x.title.contains("conteúdo de DEX"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.LOW, hit.level);
        assertTrue(hit.detail.contains("classes.dex:frida"));

        assertTrue(apk.delete());
    }

    @Test public void genericTermsDoNotTriggerSuspiciousMarker() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "assets/inject-helper.bin", new byte[]{1});
            add(zip, "assets/payload.json", new byte[]{2});
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");

        assertTrue(findings.stream()
                .noneMatch(x -> x.title.contains("instrumentação")));

        assertTrue(apk.delete());
    }

    @Test public void unreadablePathProducesFinding() {
        List<ScanFinding> findings = StaticApkAnalyzer.analyze("/definitely/missing/app.apk", "com.example.test");
        assertEquals(1, findings.size());
        assertEquals(ScanFinding.Level.LOW, findings.get(0).level);
    }

    private static void add(ZipOutputStream zip, String name, byte[] data) throws Exception {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(data);
        zip.closeEntry();
    }
}
