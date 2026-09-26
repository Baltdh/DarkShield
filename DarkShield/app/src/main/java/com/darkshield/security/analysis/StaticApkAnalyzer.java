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
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class StaticApkAnalyzer {
    private static final int MAX_ENTRIES = 10000;
    private static final long MAX_APK_BYTES = 200L * 1024L * 1024L;
    private static final int MAX_SUSPICIOUS_NAMES = 50;
    private static final int MAX_SUSPICIOUS_CONTENT_HITS = 20;
    private static final int MAX_ENTRY_CONTENT_SCAN_BYTES = 2 * 1024 * 1024;
    private static final long MAX_TOTAL_CONTENT_SCAN_BYTES = 8L * 1024L * 1024L;
    private static final long MAX_COMPRESSED_TAIL_SKIP_BYTES = 2L * 1024L * 1024L;
    private static final int MAX_CACHE_ENTRIES = 256;
    private static final int MAX_SPLITS_INSPECTED = 16;
    private static final int MAX_CODE_SPLITS_ANALYZED = 4;
    private static final long MAX_CODE_SPLIT_BYTES = 128L * 1024L * 1024L;
    private static final ThreadLocal<TimingSnapshot> LAST_TIMING = new ThreadLocal<>();

    // Process-local cache only: findings are reused when the same installed APK
    // path keeps the same size and modification timestamp. Nothing is persisted
    // to disk, and interrupted scans are never cached.
    private static final Map<CacheKey, List<ScanFinding>> ANALYSIS_CACHE =
            new LinkedHashMap<CacheKey, List<ScanFinding>>(MAX_CACHE_ENTRIES, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<CacheKey, List<ScanFinding>> eldest) {
                    return size() > MAX_CACHE_ENTRIES;
                }
            };

    // Keep distinctive markers here. Very short/generic terms such as "rat"
    // can match innocent filenames and create excessive false positives.
    private static final String[] SUSPICIOUS_MARKERS = {
            "frida", "xposed", "lsposed", "edxposed", "lspatch",
            "magisk", "zygisk", "substrate", "riru", "busybox",
            "backdoor"
    };

    private StaticApkAnalyzer() {}

    /**
     * The base APK is not the entire installed app: feature splits can carry
     * DEX and native libraries. Inspect split ZIP directories without reading
     * their contents, then analyze code-bearing splits within a shared budget.
     */
    public static List<ScanFinding> analyzeInstalled(
            String baseApkPath, String[] splitApkPaths, String packageName) {
        long startedAt = System.nanoTime();
        List<ScanFinding> out = analyze(baseApkPath, packageName);
        TimingSnapshot combined = LAST_TIMING.get();
        if (splitApkPaths == null || splitApkPaths.length == 0) return out;

        int analyzed = 0;
        int resourceOnly = 0;
        int unavailable = 0;
        int inspected = 0;
        long analyzedBytes = 0L;
        Set<String> seen = new HashSet<>();
        seen.add(baseApkPath);
        for (String path : splitApkPaths) {
            if (Thread.currentThread().isInterrupted()) throw new ScanInterruptedException();
            if (path == null || !seen.add(path)) continue;
            if (++inspected > MAX_SPLITS_INSPECTED) {
                unavailable += splitApkPaths.length - inspected + 1;
                break;
            }
            File split = new File(path);
            if (!split.isFile() || !split.canRead()) {
                unavailable++;
                continue;
            }
            boolean hasCode = false;
            boolean reachedEntryLimit = false;
            try (ZipFile zip = new ZipFile(split)) {
                java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
                int count = 0;
                while (entries.hasMoreElements()) {
                    if (Thread.currentThread().isInterrupted()) throw new ScanInterruptedException();
                    if (++count > MAX_ENTRIES) {
                        reachedEntryLimit = true;
                        break;
                    }
                    String name = entries.nextElement().getName().toLowerCase(Locale.ROOT);
                    if (isExecutableEntry(name)) {
                        hasCode = true;
                        break;
                    }
                }
            } catch (ScanInterruptedException e) {
                throw e;
            } catch (IOException | SecurityException e) {
                unavailable++;
                continue;
            }
            if (!hasCode) {
                if (reachedEntryLimit) unavailable++;
                else resourceOnly++;
                continue;
            }
            if (analyzed >= MAX_CODE_SPLITS_ANALYZED
                    || split.length() > MAX_CODE_SPLIT_BYTES - analyzedBytes) {
                unavailable++;
                continue;
            }
            analyzedBytes += split.length();
            for (ScanFinding finding : analyze(path, packageName)) {
                out.add(new ScanFinding(finding.level, finding.title,
                        "APK dividido " + split.getName() + ": " + finding.detail,
                        finding.packageName, finding.points, finding.action));
            }
            combined = TimingSnapshot.combine(combined, LAST_TIMING.get(),
                    elapsedMillis(startedAt));
            analyzed++;
        }
        if (combined != null) {
            LAST_TIMING.set(TimingSnapshot.combine(combined, null, elapsedMillis(startedAt)));
        }
        if (analyzed > 0 || unavailable > 0) {
            out.add(new ScanFinding(ScanFinding.Level.INFO,
                    "Cobertura dos APKs divididos",
                    analyzed + " parte(s) com código analisada(s); " + resourceOnly
                            + " sem DEX/bibliotecas identificados pelo nome; " + unavailable
                            + " parte(s) sem análise completa. A seleção é limitada a "
                            + MAX_SPLITS_INSPECTED + " partes inspecionadas, "
                            + MAX_CODE_SPLITS_ANALYZED + " partes com código e "
                            + (MAX_CODE_SPLIT_BYTES / (1024 * 1024)) + " MiB por aplicativo.",
                    packageName, 0,
                    unavailable > 0 ? "Revise separadamente as partes não analisadas" : null));
        }
        return out;
    }

    public static List<ScanFinding> analyze(String apkPath, String packageName) {
        long analysisStartedAt = System.nanoTime();
        LAST_TIMING.remove();
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

        CacheKey cacheKey = CacheKey.from(apk, packageName);
        if (cacheKey != null) {
            List<ScanFinding> cached = getCached(cacheKey);
            if (cached != null) {
                LAST_TIMING.set(TimingSnapshot.cacheHit(elapsedMillis(analysisStartedAt)));
                return cached;
            }
        }

        if (Thread.currentThread().isInterrupted()) {
            throw new ScanInterruptedException();
        }

        if (apk.length() > MAX_APK_BYTES) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW,
                    "APK grande demais para análise estática local",
                    "O arquivo possui " + apk.length() + " bytes; a análise foi limitada a "
                            + MAX_APK_BYTES + " bytes para evitar custo excessivo durante a varredura completa",
                    packageName, 0,
                    "Analise esse APK separadamente caso precise de inspeção profunda"));
            return out;
        }

        int entries = 0;
        int dex = 0;
        int nativeLibs = 0;
        boolean manifest = false;
        boolean resources = false;
        List<String> suspicious = new ArrayList<>();
        List<String> suspiciousResourceMarkers = new ArrayList<>();
        List<String> suspiciousContent = new ArrayList<>();
        BehaviorSignals behaviorSignals = new BehaviorSignals();
        long contentScanned = 0L;
        boolean contentSampleReadFailure = false;

        long zipStartedAt = System.nanoTime();
        try (ZipFile zip = new ZipFile(apk)) {
            java.util.Enumeration<? extends ZipEntry> e = zip.entries();
            while (e.hasMoreElements()) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new ScanInterruptedException();
                }
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

                if (containsSuspiciousMarker(lower)) {
                    if (isExecutableEntry(lower)) {
                        addCappedMarker(suspicious, name, MAX_SUSPICIOUS_NAMES);
                    } else {
                        addCappedMarker(
                                suspiciousResourceMarkers, name, MAX_SUSPICIOUS_NAMES);
                    }
                }

                boolean executablePayload = isExecutablePayload(zip, entry, lower);
                if (executablePayload && contentScanned < MAX_TOTAL_CONTENT_SCAN_BYTES) {
                    int budget = (int) Math.min(
                            MAX_ENTRY_CONTENT_SCAN_BYTES,
                            MAX_TOTAL_CONTENT_SCAN_BYTES - contentScanned);
                    byte[] sample = readContentSample(zip, entry, budget);
                    if (sample == null) {
                        contentSampleReadFailure = true;
                    } else {
                        // For oversized entries the normal sample is exactly
                        // the requested budget (head + tail). A shorter sample
                        // means a bounded portion was intentionally unavailable.
                        if (entry.getSize() > budget && sample.length < budget) {
                            contentSampleReadFailure = true;
                        }
                        contentScanned += sample.length;
                        collectContentMarkers(name, sample, suspiciousContent);
                        behaviorSignals.merge(detectBehaviorSignals(sample));
                    }
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
                        "Verifique se o arquivo analisado é realmente um APK válido")
                        .withEvidence(
                        ScanFinding.EvidenceSource.ANALYSIS_LIMIT,
                        ScanFinding.EvidenceTag.ANALYSIS_GAP));
            }

            if (!suspicious.isEmpty()) {
                suspicious.sort(StaticApkAnalyzer::compareMarker);
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
                        "Revise o app e, quando necessário, compare com a origem oficial do APK")
                        .withEvidence(
                        ScanFinding.EvidenceSource.HEURISTIC,
                        ScanFinding.EvidenceTag.STATIC_ANALYSIS));
            }

            if (!suspiciousResourceMarkers.isEmpty()) {
                suspiciousResourceMarkers.sort(StaticApkAnalyzer::compareMarker);
                StringBuilder detail = new StringBuilder();
                int shown = Math.min(6, suspiciousResourceMarkers.size());
                for (int i = 0; i < shown; i++) {
                    if (i > 0) detail.append(", ");
                    detail.append(suspiciousResourceMarkers.get(i));
                }
                if (suspiciousResourceMarkers.size() > shown) detail.append(" …");
                out.add(new ScanFinding(
                        ScanFinding.Level.INFO,
                        "Marcador suspeito em recurso não executável",
                        "Foi encontrado um marcador nominal associado a ferramentas de instrumentação em recurso(s) não executável(is): "
                                + detail
                                + ". Isso pode ser documentação, recurso empacotado ou outro conteúdo legítimo; não foi pontuado isoladamente.",
                        packageName, 0,
                        "Considere revisar somente se houver outros sinais relacionados"));
            }

            if (contentSampleReadFailure) {
                out.add(new ScanFinding(
                        ScanFinding.Level.INFO,
                        "Amostra de conteúdo indisponível",
                        "Pelo menos uma entrada de DEX/biblioteca não pôde ser lida para a amostragem estática; a ausência de marcador nessa entrada não deve ser interpretada como ausência de risco.",
                        packageName, 0,
                        "Repita a análise com um APK íntegro ou faça uma inspeção separada do arquivo"));
            }

            if (!suspiciousContent.isEmpty()) {
                suspiciousContent.sort(StaticApkAnalyzer::compareMarker);
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
                        "Foram encontrados textos associados a instrumentação dentro da amostra analisada de DEX/bibliotecas ou outro payload executável reconhecido por assinatura (início/final, quando a leitura da cauda permaneceu dentro do limite): "
                                + detail + ". Isso é um indicador heurístico e não prova comportamento malicioso.",
                        packageName, 2,
                        "Revise a origem do APK e compare o certificado/versão com a distribuição oficial")
                        .withEvidence(
                        ScanFinding.EvidenceSource.HEURISTIC,
                        ScanFinding.EvidenceTag.STATIC_ANALYSIS));
            }

            addBehaviorFindings(out, packageName, behaviorSignals);

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
        } catch (ScanInterruptedException ex) {
            throw ex;
        } catch (IOException | SecurityException ex) {
            out.add(error("Não foi possível ler a estrutura ZIP do APK", packageName));
            return out;
        }

        long zipDurationMillis = elapsedMillis(zipStartedAt);
        long contentBytes = contentScanned;
        long hashStartedAt = System.nanoTime();
        String hash = sha256(apk);
        long hashDurationMillis = elapsedMillis(hashStartedAt);
        LAST_TIMING.set(TimingSnapshot.analysis(
                zipDurationMillis, hashDurationMillis, contentBytes,
                elapsedMillis(analysisStartedAt)));
        if (hash != null) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "SHA-256 do APK",
                    hash,
                    packageName, 0, null));
        }
        if (cacheKey != null) putCached(cacheKey, out);
        return out;
    }


    public static TimingSnapshot getLastTiming() {
        return LAST_TIMING.get();
    }

    private static long elapsedMillis(long startedAt) {
        return Math.max(0L, (System.nanoTime() - startedAt) / 1_000_000L);
    }

    public static final class TimingSnapshot {
        public final boolean cacheHit;
        public final long zipMillis;
        public final long hashMillis;
        public final long contentBytesScanned;
        public final long totalMillis;

        private TimingSnapshot(boolean cacheHit, long zipMillis, long hashMillis,
                               long contentBytesScanned, long totalMillis) {
            this.cacheHit = cacheHit;
            this.zipMillis = zipMillis;
            this.hashMillis = hashMillis;
            this.contentBytesScanned = contentBytesScanned;
            this.totalMillis = totalMillis;
        }

        static TimingSnapshot cacheHit(long totalMillis) {
            return new TimingSnapshot(true, 0L, 0L, 0L, totalMillis);
        }

        static TimingSnapshot analysis(long zipMillis, long hashMillis,
                                       long contentBytesScanned, long totalMillis) {
            return new TimingSnapshot(false, zipMillis, hashMillis,
                    contentBytesScanned, totalMillis);
        }

        static TimingSnapshot combine(TimingSnapshot left, TimingSnapshot right, long totalMillis) {
            if (left == null) return right;
            if (right == null) {
                return new TimingSnapshot(left.cacheHit, left.zipMillis, left.hashMillis,
                        left.contentBytesScanned, totalMillis);
            }
            return new TimingSnapshot(left.cacheHit && right.cacheHit,
                    left.zipMillis + right.zipMillis, left.hashMillis + right.hashMillis,
                    left.contentBytesScanned + right.contentBytesScanned, totalMillis);
        }
    }

    private static List<ScanFinding> getCached(CacheKey key) {
        synchronized (ANALYSIS_CACHE) {
            List<ScanFinding> cached = ANALYSIS_CACHE.get(key);
            return cached == null ? null : new ArrayList<>(cached);
        }
    }

    private static void putCached(CacheKey key, List<ScanFinding> findings) {
        synchronized (ANALYSIS_CACHE) {
            ANALYSIS_CACHE.put(key, Collections.unmodifiableList(new ArrayList<>(findings)));
        }
    }

    private static byte[] readContentSample(ZipFile zip, ZipEntry entry, int limit) {
        if (limit <= 0) return new byte[0];
        if (entry.getSize() <= limit || entry.getSize() < 0) {
            return readRange(zip, entry, 0L, limit);
        }

        int headLimit = limit / 2;
        int tailLimit = limit - headLimit;
        byte[] head = readRange(zip, entry, 0L, headLimit);
        byte[] tail = readTail(zip, entry, tailLimit);
        if (head == null) return null;

        // Preserve the readable head when only the tail is unavailable. The
        // caller separately records that coverage is incomplete, so markers
        // found in the head remain useful without implying full coverage.
        if (tail == null) return head;

        ByteArrayOutputStream combined =
                new ByteArrayOutputStream(head.length + tail.length);
        combined.write(head, 0, head.length);
        combined.write(tail, 0, tail.length);
        return combined.toByteArray();
    }

    private static byte[] readRange(ZipFile zip, ZipEntry entry, long skipBytes, int limit) {
        if (limit <= 0) return new byte[0];
        try (InputStream in = zip.getInputStream(entry);
             ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(limit, 64 * 1024))) {
            skipFully(in, skipBytes);
            byte[] buffer = new byte[64 * 1024];
            int total = 0;
            while (total < limit) {
                if (Thread.currentThread().isInterrupted()) throw new ScanInterruptedException();
                int want = Math.min(buffer.length, limit - total);
                int read = in.read(buffer, 0, want);
                if (read < 0) break;
                if (read == 0) continue;
                out.write(buffer, 0, read);
                total += read;
            }

            // A known-size ZIP entry that ends before the requested range is
            // truncated/unreadable. Do not turn that partial sample into a
            // false "clean" result.
            if (entry.getSize() >= 0) {
                long available = Math.max(0L, entry.getSize() - skipBytes);
                long expected = Math.min((long) limit, available);
                if (total < expected) return null;
            }
            return out.toByteArray();
        } catch (IOException | SecurityException e) {
            return null;
        }
    }

    private static byte[] readTail(ZipFile zip, ZipEntry entry, int limit) {
        long size = entry.getSize();
        if (size <= 0) return new byte[0];
        long start = Math.max(0L, size - limit);

        // ZipFile can seek cheaply through STORED entries. For compressed
        // entries, skipping a very large uncompressed prefix may require
        // inflating nearly the whole stream, defeating the analysis budget.
        if (entry.getMethod() != ZipEntry.STORED
                && start >= MAX_COMPRESSED_TAIL_SKIP_BYTES) {
            // The tail is intentionally not sampled when reaching it would
            // require inflating an excessive uncompressed prefix. Report the
            // sample as unavailable instead of silently treating the head-only
            // sample as complete coverage.
            return null;
        }

        return readRange(zip, entry, start, limit);
    }

    private static void skipFully(InputStream in, long bytes) throws IOException {
        long remaining = bytes;
        while (remaining > 0) {
            if (Thread.currentThread().isInterrupted()) throw new ScanInterruptedException();
            long skipped = in.skip(remaining);
            if (skipped > 0) {
                remaining -= skipped;
                continue;
            }
            if (in.read() < 0) break;
            remaining--;
        }
    }

    private static void collectContentMarkers(
            String entryName, byte[] prefix, List<String> hits) {
        if (prefix.length == 0) return;
        String text = new String(prefix, StandardCharsets.ISO_8859_1)
                .toLowerCase(Locale.ROOT);
        for (String marker : SUSPICIOUS_MARKERS) {
            if (text.contains(marker)) {
                addCappedMarker(
                        hits, entryName + ":" + marker, MAX_SUSPICIOUS_CONTENT_HITS);
            }
        }
    }

    static BehaviorSignals detectBehaviorSignals(byte[] sample) {
        if (sample == null || sample.length == 0) return new BehaviorSignals();
        String text = new String(sample, StandardCharsets.ISO_8859_1)
                .toLowerCase(Locale.ROOT);

        BehaviorSignals signals = new BehaviorSignals();
        signals.dynamicCodeLoading = containsAny(text,
                "dalvik/system/dexclassloader",
                "dalvik/system/inmemorydexclassloader",
                "dalvik/system/delegatelastclassloader",
                "dalvik/system/dexfile");
        signals.networkFetch = containsAny(text,
                "java/net/httpurlconnection",
                "java/net/url",
                "okhttp3/",
                "android/app/downloadmanager");
        signals.shellExecution = text.contains("java/lang/processbuilder")
                || (text.contains("java/lang/runtime") && text.contains("exec"))
                || text.contains("/system/bin/sh");
        signals.webViewJavascriptBridge = text.contains("android/webkit/webview")
                && text.contains("addjavascriptinterface");
        return signals;
    }

    private static boolean containsAny(String text, String... markers) {
        for (String marker : markers) {
            if (text.contains(marker)) return true;
        }
        return false;
    }

    private static void addBehaviorFindings(
            List<ScanFinding> out, String packageName, BehaviorSignals signals) {
        if (signals.dynamicCodeLoading && signals.networkFetch) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW,
                    "Código dinâmico combinado com rede",
                    "A amostra executável contém referências a carregadores DEX e APIs de obtenção de conteúdo pela rede. Essa combinação é compatível com atualização modular legítima, mas também aparece na técnica MITRE ATT&CK Mobile T1407; a análise estática não confirma que código seja baixado ou executado.",
                    packageName, 2,
                    "Confirme a origem do aplicativo e compare certificado, versão e distribuição oficial")
                    .withEvidence(
                        ScanFinding.EvidenceSource.HEURISTIC,
                        ScanFinding.EvidenceTag.STATIC_ANALYSIS));
        } else if (signals.dynamicCodeLoading) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "Carregamento dinâmico de código referenciado",
                    "A amostra executável referencia carregadores DEX. Plugins, frameworks e atualizações modulares podem usar esse recurso legitimamente; não há evidência isolada de download ou execução maliciosa.",
                    packageName, 0,
                    "Revise apenas se houver outros sinais ou se a origem do APK for desconhecida"));
        }

        if (signals.shellExecution) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW,
                    "Execução de comandos referenciada",
                    "A amostra executável referencia APIs/caminhos capazes de iniciar comandos do sistema. Ferramentas de diagnóstico, terminais e apps com root podem usar isso legitimamente; o marcador não prova que um comando tenha sido executado.",
                    packageName, 1,
                    "Confirme se a função do aplicativo justifica executar comandos locais")
                    .withEvidence(
                        ScanFinding.EvidenceSource.HEURISTIC,
                        ScanFinding.EvidenceTag.STATIC_ANALYSIS));
        }

        if (signals.webViewJavascriptBridge && signals.networkFetch) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "Ponte WebView combinada com rede",
                    "A amostra referencia addJavascriptInterface e APIs de rede. Essa arquitetura é comum em apps híbridos, mas conteúdo remoto não confiável pode ampliar a superfície de ataque.",
                    packageName, 0,
                    "Mantenha o aplicativo atualizado e confirme sua origem; este sinal é apenas contextual"));
        }
    }

    static final class BehaviorSignals {
        boolean dynamicCodeLoading;
        boolean networkFetch;
        boolean shellExecution;
        boolean webViewJavascriptBridge;

        void merge(BehaviorSignals other) {
            if (other == null) return;
            dynamicCodeLoading |= other.dynamicCodeLoading;
            networkFetch |= other.networkFetch;
            shellExecution |= other.shellExecution;
            webViewJavascriptBridge |= other.webViewJavascriptBridge;
        }
    }

    private static void addCappedMarker(List<String> markers, String candidate, int cap) {
        if (markers.size() < cap) {
            markers.add(candidate);
            return;
        }

        int worstIndex = 0;
        for (int i = 1; i < markers.size(); i++) {
            if (compareMarker(markers.get(i), markers.get(worstIndex)) > 0) {
                worstIndex = i;
            }
        }
        if (compareMarker(candidate, markers.get(worstIndex)) < 0) {
            markers.set(worstIndex, candidate);
        }
    }

    private static int compareMarker(String left, String right) {
        int order = left.compareToIgnoreCase(right);
        return order != 0 ? order : left.compareTo(right);
    }

    private static boolean isExecutableEntry(String name) {
        return name.endsWith(".dex")
                || name.endsWith(".odex")
                || name.endsWith(".vdex")
                || (name.startsWith("lib/") && name.endsWith(".so"))
                || name.startsWith("bin/")
                || (name.startsWith("assets/") && (
                        name.endsWith(".dex") || name.endsWith(".so")
                                || name.endsWith(".odex") || name.endsWith(".vdex")));
    }

    /**
     * Prefer the path/extension signal, but also recognize disguised executable
     * payloads from their file signatures so a payload named e.g. .bin or .dat
     * still receives bounded content inspection.
     */
    private static boolean isExecutablePayload(
            ZipFile zip, ZipEntry entry, String lowerName) {
        if (isExecutableEntry(lowerName)) return true;

        byte[] magic = readRange(zip, entry, 0L, 4);
        if (magic == null || magic.length < 4) return false;

        // Dalvik/ART bytecode: dex\n / dey\n (ODEX) and VDEX containers.
        if ((magic[0] == 'd' && magic[1] == 'e' && magic[2] == 'x' && magic[3] == '\n')
                || (magic[0] == 'd' && magic[1] == 'e' && magic[2] == 'y' && magic[3] == '\n')
                || (magic[0] == 'v' && magic[1] == 'd' && magic[2] == 'e' && magic[3] == 'x')) {
            return true;
        }

        // ELF native executable/shared-object signature.
        return (magic[0] & 0xFF) == 0x7F
                && magic[1] == 'E'
                && magic[2] == 'L'
                && magic[3] == 'F';
    }

    private static boolean containsSuspiciousMarker(String name) {
        for (String marker : SUSPICIOUS_MARKERS) {
            if (name.contains(marker)) return true;
        }
        return false;
    }


    private static final class CacheKey {
        final String path;
        final String packageName;
        final long size;
        final long lastModified;

        private CacheKey(String path, String packageName, long size, long lastModified) {
            this.path = path;
            this.packageName = packageName;
            this.size = size;
            this.lastModified = lastModified;
        }

        static CacheKey from(File file, String packageName) {
            try {
                return new CacheKey(file.getCanonicalPath(), packageName, file.length(), file.lastModified());
            } catch (IOException | SecurityException e) {
                return null;
            }
        }

        @Override public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof CacheKey)) return false;
            CacheKey other = (CacheKey) o;
            return size == other.size
                    && lastModified == other.lastModified
                    && path.equals(other.path)
                    && java.util.Objects.equals(packageName, other.packageName);
        }

        @Override public int hashCode() {
            return java.util.Objects.hash(path, packageName, size, lastModified);
        }
    }

    private static final class ScanInterruptedException extends RuntimeException {
        ScanInterruptedException() { super("A verificação foi interrompida."); }
    }

    private static ScanFinding error(String detail, String packageName) {
        return new ScanFinding(
                ScanFinding.Level.LOW,
                "Falha na análise estática",
                detail,
                packageName, 1,
                "Repita a análise com um APK legível e íntegro")
                .withEvidence(
                        ScanFinding.EvidenceSource.ANALYSIS_LIMIT,
                        ScanFinding.EvidenceTag.ANALYSIS_GAP);
    }

    private static String sha256(File file) {
        try (FileInputStream in = new FileInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                if (Thread.currentThread().isInterrupted()) throw new ScanInterruptedException();
                digest.update(buffer, 0, read);
            }
            byte[] bytes = digest.digest();
            StringBuilder out = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) out.append(String.format(Locale.ROOT, "%02X", b));
            return out.toString();
        } catch (ScanInterruptedException e) {
            throw e;
        } catch (Exception e) {
            return null;
        }
    }
}
