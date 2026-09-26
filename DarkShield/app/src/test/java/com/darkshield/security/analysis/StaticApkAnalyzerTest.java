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

    @Test public void installedAppIncludesCodeFromFeatureSplit() throws Exception {
        File base = File.createTempFile("darkshield-base", ".apk");
        File feature = File.createTempFile("darkshield-feature", ".apk");
        try {
            try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(base))) {
                add(zip, "AndroidManifest.xml", new byte[]{1});
                add(zip, "classes.dex", new byte[]{1});
            }
            try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(feature))) {
                add(zip, "AndroidManifest.xml", new byte[]{1});
                add(zip, "classes.dex", "frida".getBytes("UTF-8"));
            }

            List<ScanFinding> findings = StaticApkAnalyzer.analyzeInstalled(
                    base.getAbsolutePath(), new String[]{feature.getAbsolutePath()}, "com.example.test");
            assertTrue(findings.stream().anyMatch(x -> x.title.equals(
                    "Marcadores suspeitos no conteúdo de DEX/bibliotecas")
                    && x.detail.contains(feature.getName())));
            assertEquals(2, findings.stream().filter(x -> x.title.equals("SHA-256 do APK")).count());
            assertTrue(findings.stream().anyMatch(x -> x.title.equals("Cobertura dos APKs divididos")
                    && x.detail.contains("1 parte(s) com código analisada(s)")));
            assertTrue(StaticApkAnalyzer.getLastTiming().contentBytesScanned >= 6L);
        } finally {
            assertTrue(base.delete());
            assertTrue(feature.delete());
        }
    }

    @Test public void resourceSplitIsSkippedAndUnreadableSplitIsReported() throws Exception {
        File base = File.createTempFile("darkshield-base", ".apk");
        File resources = File.createTempFile("darkshield-resources", ".apk");
        try {
            try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(base))) {
                add(zip, "AndroidManifest.xml", new byte[]{1});
                add(zip, "classes.dex", new byte[]{1});
            }
            try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(resources))) {
                add(zip, "AndroidManifest.xml", new byte[]{1});
                add(zip, "res/raw/frida.txt", new byte[]{1});
            }

            List<ScanFinding> findings = StaticApkAnalyzer.analyzeInstalled(
                    base.getAbsolutePath(), new String[]{resources.getAbsolutePath(),
                            "/definitely/missing/split.apk"}, "com.example.test");
            assertEquals(1, findings.stream().filter(x -> x.title.equals("SHA-256 do APK")).count());
            assertTrue(findings.stream().anyMatch(x -> x.title.equals("Cobertura dos APKs divididos")
                    && x.detail.contains("1 sem DEX/bibliotecas")
                    && x.detail.contains("1 parte(s) sem análise completa")));
        } finally {
            assertTrue(base.delete());
            assertTrue(resources.delete());
        }
    }

    @Test public void splitBudgetLeavesExplicitIncompleteCoverage() throws Exception {
        File base = File.createTempFile("darkshield-base", ".apk");
        File[] splits = new File[5];
        try {
            try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(base))) {
                add(zip, "AndroidManifest.xml", new byte[]{1});
                add(zip, "classes.dex", new byte[]{1});
            }
            String[] paths = new String[splits.length];
            for (int i = 0; i < splits.length; i++) {
                splits[i] = File.createTempFile("darkshield-split-" + i, ".apk");
                paths[i] = splits[i].getAbsolutePath();
                try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(splits[i]))) {
                    add(zip, "AndroidManifest.xml", new byte[]{1});
                    add(zip, "classes.dex", new byte[]{(byte) i});
                }
            }
            List<ScanFinding> findings = StaticApkAnalyzer.analyzeInstalled(
                    base.getAbsolutePath(), paths, "com.example.test");
            assertEquals(5, findings.stream().filter(x -> x.title.equals("SHA-256 do APK")).count());
            assertTrue(findings.stream().anyMatch(x -> x.title.equals("Cobertura dos APKs divididos")
                    && x.detail.contains("4 parte(s) com código analisada(s)")
                    && x.detail.contains("1 parte(s) sem análise completa")));
        } finally {
            assertTrue(base.delete());
            for (File split : splits) if (split != null) assertTrue(split.delete());
        }
    }

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

        StaticApkAnalyzer.TimingSnapshot timing = StaticApkAnalyzer.getLastTiming();
        assertTrue(timing != null);
        assertTrue(!timing.cacheHit);
        assertTrue(timing.zipMillis >= 0L);
        assertTrue(timing.hashMillis >= 0L);
        assertTrue(timing.contentBytesScanned > 0L);

        assertTrue(apk.delete());
    }

    @Test public void modifiedApkInvalidatesStaticAnalysisCache() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "classes.dex", new byte[]{1, 2, 3});
        }

        List<ScanFinding> first = StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");
        String firstHash = first.stream()
                .filter(x -> x.title.equals("SHA-256 do APK"))
                .map(x -> x.detail)
                .findFirst().orElse(null);
        assertTrue(firstHash != null);

        assertTrue(apk.delete());
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "classes.dex", new byte[]{1, 2, 4});
        }
        assertTrue(apk.setLastModified(Math.max(System.currentTimeMillis(), apk.lastModified() + 2000L)));

        List<ScanFinding> second = StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");
        String secondHash = second.stream()
                .filter(x -> x.title.equals("SHA-256 do APK"))
                .map(x -> x.detail)
                .findFirst().orElse(null);
        assertTrue(secondHash != null);
        assertTrue(!firstHash.equals(secondHash));

        assertTrue(apk.delete());
    }

    @Test public void staticMarkerDetailsAreDeterministicAcrossZipOrder() throws Exception {
        File first = File.createTempFile("darkshield-test", ".apk");
        File second = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(first))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "lib/arm64-v8a/libxposed.so", new byte[]{1});
            add(zip, "lib/arm64-v8a/libfrida.so", new byte[]{1});
        }
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(second))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "lib/arm64-v8a/libfrida.so", new byte[]{1});
            add(zip, "lib/arm64-v8a/libxposed.so", new byte[]{1});
        }

        ScanFinding firstHit = StaticApkAnalyzer.analyze(
                first.getAbsolutePath(), "com.example.test").stream()
                .filter(x -> x.title.contains("Nomes de arquivos associados"))
                .findFirst().orElse(null);
        ScanFinding secondHit = StaticApkAnalyzer.analyze(
                second.getAbsolutePath(), "com.example.test").stream()
                .filter(x -> x.title.contains("Nomes de arquivos associados"))
                .findFirst().orElse(null);

        assertTrue(firstHit != null);
        assertTrue(secondHit != null);
        assertEquals(firstHit.detail, secondHit.detail);

        assertTrue(first.delete());
        assertTrue(second.delete());
    }

    @Test public void cappedSuspiciousNamesAreDeterministicAcrossZipOrder() throws Exception {
        File first = File.createTempFile("darkshield-test", ".apk");
        File second = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(first))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            for (int i = 60; i >= 1; i--) {
                add(zip, String.format("lib/arm64-v8a/libfrida-%02d.so", i), new byte[]{1});
            }
        }
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(second))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            for (int i = 1; i <= 60; i++) {
                add(zip, String.format("lib/arm64-v8a/libfrida-%02d.so", i), new byte[]{1});
            }
        }

        ScanFinding firstHit = StaticApkAnalyzer.analyze(
                first.getAbsolutePath(), "com.example.test").stream()
                .filter(x -> x.title.equals(
                        "Nomes de arquivos associados a ferramentas de instrumentação"))
                .findFirst().orElse(null);
        ScanFinding secondHit = StaticApkAnalyzer.analyze(
                second.getAbsolutePath(), "com.example.test").stream()
                .filter(x -> x.title.equals(
                        "Nomes de arquivos associados a ferramentas de instrumentação"))
                .findFirst().orElse(null);

        assertTrue(firstHit != null);
        assertTrue(secondHit != null);
        assertEquals(firstHit.detail, secondHit.detail);
        assertTrue(firstHit.detail.contains("libfrida-01.so"));
        assertTrue(firstHit.detail.contains("libfrida-06.so"));
        assertTrue(!firstHit.detail.contains("libfrida-60.so"));

        assertTrue(first.delete());
        assertTrue(second.delete());
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

    @Test public void suspiciousNamesAreCaseInsensitive() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "lib/arm64-v8a/libFRIDA-helper.so", new byte[]{1});
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");

        ScanFinding hit = findings.stream()
                .filter(x -> x.title.contains("instrumentação"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.LOW, hit.level);
        assertTrue(hit.detail.contains("lib/arm64-v8a/libFRIDA-helper.so"));

        assertTrue(apk.delete());
    }

    @Test public void cappedContentMarkersAreDeterministicAcrossZipOrder() throws Exception {
        File first = File.createTempFile("darkshield-test", ".apk");
        File second = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(first))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            for (int i = 21; i >= 1; i--) {
                add(zip, String.format("classes%02d.dex", i),
                        ("marker-frida-" + i).getBytes("ISO-8859-1"));
            }
        }
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(second))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            for (int i = 1; i <= 21; i++) {
                add(zip, String.format("classes%02d.dex", i),
                        ("marker-frida-" + i).getBytes("ISO-8859-1"));
            }
        }

        ScanFinding firstHit = StaticApkAnalyzer.analyze(
                first.getAbsolutePath(), "com.example.test").stream()
                .filter(x -> x.title.equals(
                        "Marcadores suspeitos no conteúdo de DEX/bibliotecas"))
                .findFirst().orElse(null);
        ScanFinding secondHit = StaticApkAnalyzer.analyze(
                second.getAbsolutePath(), "com.example.test").stream()
                .filter(x -> x.title.equals(
                        "Marcadores suspeitos no conteúdo de DEX/bibliotecas"))
                .findFirst().orElse(null);

        assertTrue(firstHit != null);
        assertTrue(secondHit != null);
        assertEquals(firstHit.detail, secondHit.detail);
        assertTrue(firstHit.detail.contains("classes01.dex:frida"));
        assertTrue(firstHit.detail.contains("classes06.dex:frida"));
        assertTrue(!firstHit.detail.contains("classes21.dex:frida"));

        assertTrue(first.delete());
        assertTrue(second.delete());
    }

    @Test public void suspiciousContentMarkersAreCaseInsensitive() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "classes.dex", "native-FRIDA-marker".getBytes("ISO-8859-1"));
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

    @Test public void suspiciousResourceMarkersAreCaseInsensitive() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "assets/FRIDA-agent.bin", new byte[]{1});
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");
        ScanFinding hit = findings.stream()
                .filter(x -> x.title.contains("recurso não executável"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.INFO, hit.level);
        assertEquals(0, hit.points);
        assertTrue(hit.detail.contains("assets/FRIDA-agent.bin"));

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

    @Test public void compressedTailAtSkipLimitDoesNotExceedBudget() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        byte[] data = new byte[(3 * 1024 * 1024) + 256];
        byte[] marker = "boundary-tail-frida-marker".getBytes("ISO-8859-1");
        System.arraycopy(marker, 0, data, data.length - marker.length, marker.length);

        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "classes.dex", data);
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");

        assertTrue(findings.stream()
                .noneMatch(x -> x.title.contains("conteúdo de DEX")));
        assertTrue(findings.stream()
                .anyMatch(x -> x.title.equals("Estrutura ZIP do APK")));

        assertTrue(apk.delete());
    }

    @Test public void veryFarCompressedTailDoesNotForceLargeSkip() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        byte[] data = new byte[(4 * 1024 * 1024) + 256];
        byte[] marker = "far-tail-frida-marker".getBytes("ISO-8859-1");
        System.arraycopy(marker, 0, data, data.length - marker.length, marker.length);

        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "classes.dex", data);
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");

        assertTrue(findings.stream()
                .noneMatch(x -> x.title.contains("conteúdo de DEX")));
        assertTrue(findings.stream()
                .anyMatch(x -> x.title.equals("Estrutura ZIP do APK")));
        ScanFinding unavailable = findings.stream()
                .filter(x -> x.title.equals("Amostra de conteúdo indisponível"))
                .findFirst().orElse(null);
        assertTrue(unavailable != null);
        assertEquals(0, unavailable.points);

        assertTrue(apk.delete());
    }

    @Test public void partialCompressedSampleReportsCoverageAndKeepsHeadDetection() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        byte[] data = new byte[(4 * 1024 * 1024) + 256];
        byte[] headMarker = "head-frida-marker".getBytes("ISO-8859-1");
        byte[] tailMarker = "tail-xposed-marker".getBytes("ISO-8859-1");
        System.arraycopy(headMarker, 0, data, 1024, headMarker.length);
        System.arraycopy(tailMarker, 0, data, data.length - tailMarker.length, tailMarker.length);

        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "classes.dex", data);
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");

        ScanFinding contentHit = findings.stream()
                .filter(x -> x.title.contains("conteúdo de DEX"))
                .findFirst().orElse(null);
        ScanFinding unavailable = findings.stream()
                .filter(x -> x.title.equals("Amostra de conteúdo indisponível"))
                .findFirst().orElse(null);

        assertTrue(contentHit != null);
        assertTrue(contentHit.detail.contains("classes.dex:frida"));
        assertTrue(unavailable != null);
        assertEquals(0, unavailable.points);

        assertTrue(apk.delete());
    }

    @Test public void suspiciousContentInsideExecutableAssetIsDetected() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "assets/payload.dex",
                    "embedded-frida-loader".getBytes("ISO-8859-1"));
        }

        List<ScanFinding> findings = StaticApkAnalyzer.analyze(
                apk.getAbsolutePath(), "com.example.test");
        ScanFinding hit = findings.stream()
                .filter(x -> x.title.contains("conteúdo de DEX"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.LOW, hit.level);
        assertTrue(hit.detail.contains("assets/payload.dex:frida"));

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

    @Test public void disguisedElfPayloadIsScannedByMagicSignature() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        byte[] data = new byte[128];
        data[0] = 0x7F;
        data[1] = 'E';
        data[2] = 'L';
        data[3] = 'F';
        byte[] marker = "frida-loader".getBytes("ISO-8859-1");
        System.arraycopy(marker, 0, data, 16, marker.length);

        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "assets/payload.bin", data);
        }

        List<ScanFinding> findings =
                StaticApkAnalyzer.analyze(apk.getAbsolutePath(), "com.example.test");

        ScanFinding hit = findings.stream()
                .filter(x -> x.title.equals(
                        "Marcadores suspeitos no conteúdo de DEX/bibliotecas"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.LOW, hit.level);
        assertEquals(2, hit.points);
        assertTrue(hit.detail.contains("assets/payload.bin:frida"));

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

    @Test public void dynamicCodeLoaderCombinedWithNetworkIsFlaggedHeuristically() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "classes.dex",
                    ("Ldalvik/system/DexClassLoader;"
                            + "Ljava/net/HttpURLConnection;").getBytes("ISO-8859-1"));
        }

        ScanFinding hit = StaticApkAnalyzer.analyze(
                apk.getAbsolutePath(), "com.example.test").stream()
                .filter(x -> x.title.equals("Código dinâmico combinado com rede"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.LOW, hit.level);
        assertEquals(2, hit.points);
        assertTrue(hit.detail.contains("T1407"));
        assertTrue(hit.detail.contains("não confirma"));
        assertTrue(apk.delete());
    }

    @Test public void dynamicCodeLoaderWithoutNetworkRemainsInformational() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "classes.dex",
                    "Ldalvik/system/InMemoryDexClassLoader;".getBytes("ISO-8859-1"));
        }

        ScanFinding hit = StaticApkAnalyzer.analyze(
                apk.getAbsolutePath(), "com.example.test").stream()
                .filter(x -> x.title.equals("Carregamento dinâmico de código referenciado"))
                .findFirst().orElse(null);

        assertTrue(hit != null);
        assertEquals(ScanFinding.Level.INFO, hit.level);
        assertEquals(0, hit.points);
        assertTrue(apk.delete());
    }

    @Test public void networkApiAloneDoesNotImplyDynamicCodeLoading() throws Exception {
        StaticApkAnalyzer.BehaviorSignals signals = StaticApkAnalyzer.detectBehaviorSignals(
                "Ljava/net/HttpURLConnection;".getBytes("ISO-8859-1"));

        assertTrue(signals.networkFetch);
        assertTrue(!signals.dynamicCodeLoading);
        assertTrue(!signals.shellExecution);
    }

    @Test public void detectsShellAndWebViewBridgeAsSeparateContext() throws Exception {
        File apk = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            add(zip, "classes.dex",
                    ("Ljava/lang/ProcessBuilder;"
                            + "Landroid/webkit/WebView;addJavascriptInterface"
                            + "Lokhttp3/OkHttpClient;").getBytes("ISO-8859-1"));
        }

        List<ScanFinding> findings = StaticApkAnalyzer.analyze(
                apk.getAbsolutePath(), "com.example.test");
        assertTrue(findings.stream().anyMatch(x ->
                x.title.equals("Execução de comandos referenciada")
                        && x.level == ScanFinding.Level.LOW));
        assertTrue(findings.stream().anyMatch(x ->
                x.title.equals("Ponte WebView combinada com rede")
                        && x.level == ScanFinding.Level.INFO));
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

    @Test public void cappedResourceMarkersAreDeterministicAcrossZipOrder() throws Exception {
        File first = File.createTempFile("darkshield-test", ".apk");
        File second = File.createTempFile("darkshield-test", ".apk");
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(first))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            for (int i = 51; i >= 1; i--) {
                add(zip, String.format("res/raw/frida-resource-%02d.txt", i),
                        ("resource-" + i).getBytes("ISO-8859-1"));
            }
        }
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(second))) {
            add(zip, "AndroidManifest.xml", new byte[]{1});
            for (int i = 1; i <= 51; i++) {
                add(zip, String.format("res/raw/frida-resource-%02d.txt", i),
                        ("resource-" + i).getBytes("ISO-8859-1"));
            }
        }

        ScanFinding firstHit = StaticApkAnalyzer.analyze(
                first.getAbsolutePath(), "com.example.test").stream()
                .filter(x -> x.title.equals("Marcador suspeito em recurso não executável"))
                .findFirst().orElse(null);
        ScanFinding secondHit = StaticApkAnalyzer.analyze(
                second.getAbsolutePath(), "com.example.test").stream()
                .filter(x -> x.title.equals("Marcador suspeito em recurso não executável"))
                .findFirst().orElse(null);

        assertTrue(firstHit != null);
        assertTrue(secondHit != null);
        assertEquals(firstHit.detail, secondHit.detail);
        assertTrue(firstHit.detail.contains("frida-resource-01.txt"));
        assertTrue(firstHit.detail.contains("frida-resource-06.txt"));
        assertTrue(!firstHit.detail.contains("frida-resource-51.txt"));

        assertTrue(first.delete());
        assertTrue(second.delete());
    }



}
