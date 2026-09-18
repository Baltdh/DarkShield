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

    @Test public void suspiciousContentNearNativeLibraryTailIsDetected() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        byte[] data = new byte[(2 * 1024 * 1024) + 256];
        byte[] marker = "tail-xposed-marker".getBytes("ISO-8859-1");
        System.arraycopy(marker, 0, data, data.length - marker.length, marker.length);

        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "lib/arm64-v8a/libdemo.so", data);
        }

        List<ScanFinding> findings = StaticApkAnalyzer.analyze(
                apk.getAbsolutePath(), "com.example.test");
        ScanFinding hit = findings.stream()
                .filter(x -> x.title.contains("conteúdo de DEX"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.LOW, hit.level);
        assertTrue(hit.detail.contains("lib/arm64-v8a/libdemo.so:xposed"));

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

    @Test public void multipleDexFilesAreInformationalOnly() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            for (int i = 1; i <= 5; i++) {
                add(zip, i == 1 ? "classes.dex" : "classes" + i + ".dex",
                        new byte[]{(byte) i});
            }
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");
        ScanFinding hit = findings.stream()
                .filter(x -> x.title.equals("Múltiplos arquivos DEX"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.INFO, hit.level);
        assertEquals(0, hit.points);
        assertTrue(hit.detail.contains("5 arquivos DEX"));

        assertTrue(apk.delete());
    }

    @Test public void oversizedApkIsRejectedBeforeZipProcessing() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try {
            try (java.io.RandomAccessFile out = new java.io.RandomAccessFile(apk, "rw")) {
                out.setLength(200L * 1024L * 1024L + 1L);
            }

            List<ScanFinding> findings =
                    StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");
            assertEquals(1, findings.size());
            assertEquals(
                    "APK grande demais para análise estática local",
                    findings.get(0).title);
            assertEquals(ScanFinding.Level.LOW, findings.get(0).level);
            assertEquals(0, findings.get(0).points);
            assertTrue(findings.get(0).detail.contains("bytes"));
        } finally {
            assertTrue(apk.delete());
        }
    }

    @Test public void missingManifestProducesMediumFinding() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "classes.dex", new byte[]{1, 2, 3});
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");
        ScanFinding hit = findings.stream()
                .filter(x -> x.title.equals("Manifesto do APK ausente"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.MEDIUM, hit.level);
        assertEquals(3, hit.points);

        assertTrue(apk.delete());
    }

    @Test public void suspiciousMarkerInOrdinaryResourceDoesNotAddRiskPoints() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "res/raw/magisk_documentation.txt", new byte[]{1});
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");
        ScanFinding hit = findings.stream()
                .filter(x -> x.title.equals("Marcador suspeito em recurso não executável"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.INFO, hit.level);
        assertEquals(0, hit.points);
        assertTrue(findings.stream()
                .noneMatch(x -> x.title.equals(
                        "Nomes de arquivos associados a ferramentas de instrumentação")));

        assertTrue(apk.delete());
    }


    @Test public void executableAssetMarkerRemainsHeuristic() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "assets/frida-helper.so", new byte[]{1});
            add(zip, "assets/xposed-hook.odex", new byte[]{2});
            add(zip, "bin/magisk-tool", new byte[]{3});
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");

        ScanFinding hit = findings.stream()
                .filter(x -> x.title.equals(
                        "Nomes de arquivos associados a ferramentas de instrumentação"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.LOW, hit.level);
        assertEquals(2, hit.points);
        assertTrue(hit.detail.contains("assets/frida-helper.so"));
        assertTrue(hit.detail.contains("assets/xposed-hook.odex"));
        assertTrue(hit.detail.contains("bin/magisk-tool"));

        assertTrue(apk.delete());
    }

    @Test public void corruptedZipProducesControlledFinding() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try {
            try (FileOutputStream out = new FileOutputStream(apk)) {
                out.write("not-a-valid-zip".getBytes("ISO-8859-1"));
            }

            List<ScanFinding> findings =
                    StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");
            assertEquals(1, findings.size());
            assertEquals("Falha na análise estática", findings.get(0).title);
            assertEquals(ScanFinding.Level.LOW, findings.get(0).level);
            assertEquals(1, findings.get(0).points);
        } finally {
            assertTrue(apk.delete());
        }
    }


    @Test public void tooManyZipEntriesAreCapped() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try {
            try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
                add(zip, "AndroidManifest.xml", new byte[]{1});
                for (int i = 0; i < 10000; i++) {
                    add(zip, "assets/entry" + i + ".bin", new byte[]{1});
                }
            }

            List<ScanFinding> findings =
                    StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");

            ScanFinding limit = findings.stream()
                    .filter(x -> x.title.equals("APK com muitas entradas"))
                    .findFirst().orElse(null);
            assertTrue(limit != null);
            assertEquals(ScanFinding.Level.INFO, limit.level);
            assertEquals(0, limit.points);
            assertTrue(limit.detail.contains("10000 entradas"));

            ScanFinding structure = findings.stream()
                    .filter(x -> x.title.equals("Estrutura ZIP do APK"))
                    .findFirst().orElse(null);
            assertTrue(structure != null);
            assertTrue(structure.detail.contains("Entradas: 10001"));

            assertTrue(apk.delete());
        } catch (Throwable t) {
            apk.delete();
            throw t;
        }
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
