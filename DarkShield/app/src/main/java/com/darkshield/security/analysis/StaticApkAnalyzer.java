package com.darkshield.security.analysis;

import com.darkshield.security.ScanFinding;
import java.io.File;
import java.io.FileInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class StaticApkAnalyzer {
    private static final int MAX_ENTRIES = 10000;
    private static final long MAX_APK_BYTES = 200L * 1024L * 1024L;
    private static final int MAX_SUSPICIOUS_NAMES = 50;
    private static final int MAX_SUSPICIOUS_CONTENT_HITS = 20;
    private static final int MAX_ENTRY_CONTENT_SCAN_BYTES = 2 * 1024 * 1024;
    private static final long MAX_TOTAL_CONTENT_SCAN_BYTES = 8L * 1024L * 1024L;

    // Keep distinctive markers here. Very short/generic terms such as "rat"
    // can match innocent filenames and create excessive false positives.
    private static final String[] SUSPICIOUS_MARKERS = {
            "frida", "xposed", "lsposed", "edxposed", "lspatch",
            "magisk", "zygisk", "substrate", "riru", "busybox",
            "inject", "backdoor", "payload"
    };

    private StaticApkAnalyzer() {}

    public static List<ScanFinding> analyze(String apkPath, String packageName) {
        List<ScanFinding> out = new ArrayList<>();
        if (apkPath == null || apkPath.trim().isEmpty()) {
            out.add(error("Caminho do APK ausente", packageName));
            return out;
        }

        File apk = new File(apkPath);
        if (!apk.isFile() || !apk.canRead()) {
            out.add(error("APK não encontrado ou sem acesso de leitura", packageName));
            return out;
        }

        if (apk.length() > MAX_APK_BYTES) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW,
                    "APK grande demais para análise estática local",
                    "O arquivo possui " + apk.length() + " bytes; a análise foi limitada a "
                            + MAX_APK_BYTES + " bytes para evitar custo excessivo durante a varredura completa",
                    packageName, 1,
                    "Analise esse APK separadamente caso precise de inspeção profunda"));
            return out;
        }

        int entries = 0;
        int dex = 0;
        int nativeLibs = 0;
        boolean manifest = false;
        boolean resources = false;
        List<String> suspicious = new ArrayList<>();
        List<String> suspiciousContent = new ArrayList<>();
        long contentScanned = 0L;

        try (ZipFile zip = new ZipFile(apk)) {
            java.util.Enumeration<? extends ZipEntry> e = zip.entries();
            while (e.hasMoreElements()) {
                ZipEntry entry = e.nextElement();
                if (++entries > MAX_ENTRIES) {
                    out.add(new ScanFinding(
                            ScanFinding.Level.INFO,
                            "APK com muitas entradas",
                            "A análise foi limitada após " + MAX_ENTRIES
                                    + " entradas para manter o custo previsível",
                            packageName, 0,
                            "Considere uma análise ADB/forense separada para esse APK"));
                    break;
                }

                String name = entry.getName();
                String lower = name.toLowerCase(Locale.ROOT);

                if ("androidmanifest.xml".equals(lower)) manifest = true;
                if ("resources.arsc".equals(lower)) resources = true;
                if (lower.endsWith(".dex")) dex++;
                if (lower.startsWith("lib/") && lower.endsWith(".so")) nativeLibs++;

                if (containsSuspiciousMarker(lower) && suspicious.size() < MAX_SUSPICIOUS_NAMES) {
                    suspicious.add(name);
                }

                boolean binaryCode = lower.endsWith(".dex")
                        || (lower.startsWith("lib/") && lower.endsWith(".so"));
                if (binaryCode && contentScanned < MAX_TOTAL_CONTENT_SCAN_BYTES
                        && suspiciousContent.size() < MAX_SUSPICIOUS_CONTENT_HITS) {
                    int budget = (int) Math.min(
                            MAX_ENTRY_CONTENT_SCAN_BYTES,
                            MAX_TOTAL_CONTENT_SCAN_BYTES - contentScanned);
                    byte[] prefix = readPrefix(zip, entry, budget);
                    contentScanned += prefix.length;
                    collectContentMarkers(name, prefix, suspiciousContent);
                }
            }

            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "Estrutura ZIP do APK",
                    "Entradas: " + entries + "; DEX: " + dex
                            + "; bibliotecas nativas: " + nativeLibs
                            + "; AndroidManifest.xml: " + manifest
                            + "; resources.arsc: " + resources,
                    packageName, 0, null));

            if (!manifest) {
                out.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Manifesto do APK ausente",
                        "AndroidManifest.xml não foi encontrado na estrutura ZIP",
                        packageName, 3,
                        "Verifique se o arquivo analisado é realmente um APK válido"));
            }

            if (!suspicious.isEmpty()) {
                StringBuilder detail = new StringBuilder();
                int shown = Math.min(6, suspicious.size());
                for (int i = 0; i < shown; i++) {
                    if (i > 0) detail.append(", ");
                    detail.append(suspicious.get(i));
                }
                if (suspicious.size() > shown) detail.append(" …");
                out.add(new ScanFinding(
                        ScanFinding.Level.LOW,
                        "Nomes de arquivos associados a ferramentas de instrumentação",
                        "Marcadores estáticos encontrados: " + detail
                                + ". Isso é um indicador heurístico e não prova comportamento malicioso.",
                        packageName, 2,
                        "Revise o app e, quando necessário, compare com a origem oficial do APK"));
            }

            if (!suspiciousContent.isEmpty()) {
                StringBuilder detail = new StringBuilder();
                int shown = Math.min(6, suspiciousContent.size());
                for (int i = 0; i < shown; i++) {
                    if (i > 0) detail.append(", ");
                    detail.append(suspiciousContent.get(i));
                }
                if (suspiciousContent.size() > shown) detail.append(" …");
                out.add(new ScanFinding(
                        ScanFinding.Level.LOW,
                        "Marcadores suspeitos no conteúdo de DEX/bibliotecas",
                        "Foram encontrados textos associados a instrumentação dentro do prefixo analisado de DEX/bibliotecas: "
                                + detail + ". Isso é um indicador heurístico e não prova comportamento malicioso.",
                        packageName, 2,
                        "Revise a origem do APK e compare o certificado/versão com a distribuição oficial"));
            }

            if (dex == 0) {
                out.add(new ScanFinding(
                        ScanFinding.Level.INFO,
                        "DEX não identificado",
                        "Nenhuma entrada .dex foi encontrada; o arquivo pode não conter código Dalvik convencional",
                        packageName, 0, null));
            } else if (dex > 4) {
                out.add(new ScanFinding(
                        ScanFinding.Level.INFO,
                        "Múltiplos arquivos DEX",
                        "O APK contém " + dex + " arquivos DEX",
                        packageName, 0,
                        "Quantidade elevada pode ser legítima; revise apenas junto de outros indicadores"));
            }
        } catch (IOException | SecurityException ex) {
            out.add(error("Não foi possível ler a estrutura ZIP do APK", packageName));
            return out;
        }

        String hash = sha256(apk);
        if (hash != null) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "SHA-256 do APK",
                    hash,
                    packageName, 0, null));
        }
        return out;
    }

    private static byte[] readPrefix(ZipFile zip, ZipEntry entry, int limit) {
        if (limit <= 0) return new byte[0];
        try (InputStream in = zip.getInputStream(entry);
             ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(limit, 64 * 1024))) {
            byte[] buffer = new byte[64 * 1024];
            int total = 0;
            while (total < limit) {
                int want = Math.min(buffer.length, limit - total);
                int read = in.read(buffer, 0, want);
                if (read < 0) break;
                if (read == 0) continue;
                out.write(buffer, 0, read);
                total += read;
            }
            return out.toByteArray();
        } catch (IOException | SecurityException e) {
            return new byte[0];
        }
    }

    private static void collectContentMarkers(
            String entryName, byte[] prefix, List<String> hits) {
        if (prefix.length == 0) return;
        String text = new String(prefix, StandardCharsets.ISO_8859_1)
                .toLowerCase(Locale.ROOT);
        for (String marker : SUSPICIOUS_MARKERS) {
            if (hits.size() >= MAX_SUSPICIOUS_CONTENT_HITS) return;
            if (text.contains(marker)) hits.add(entryName + ":" + marker);
        }
    }

    private static boolean containsSuspiciousMarker(String name) {
        for (String marker : SUSPICIOUS_MARKERS) {
            if (name.contains(marker)) return true;
        }
        return false;
    }

    private static ScanFinding error(String detail, String packageName) {
        return new ScanFinding(
                ScanFinding.Level.LOW,
                "Falha na análise estática",
                detail,
                packageName, 1,
                "Repita a análise com um APK legível e íntegro");
    }

    private static String sha256(File file) {
        try (FileInputStream in = new FileInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) != -1) digest.update(buffer, 0, read);
            byte[] bytes = digest.digest();
            StringBuilder out = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) out.append(String.format(Locale.ROOT, "%02X", b));
            return out.toString();
        } catch (Exception e) {
            return null;
        }
    }
}
