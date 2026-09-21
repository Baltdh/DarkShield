package com.darkshield.security;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.net.Uri;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ClickableSpan;
import android.view.View;
import android.widget.Toast;
import android.widget.Button;
import android.widget.TextView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.CheckBox;
import java.util.ArrayList;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends android.app.Activity {
    private TextView score, summary, report, lastScan, nextAction, coverageHint;
    private TextView countCritical, countHigh, countMedium, countLow;
    private ScanProgressView scanProgress;
    private TextView scanProgressStage;
    private View progressContainer;
    private Button scan, cancelScan, remediation, securitySettings, share, copy;
    private ScanReport lastScanReport;
    private ScanTimingTracker scanTimingTracker;
    private String lastReport = "";
    private static final String PREFS = "darkshield_ui";
    private static final String KEY_LAST_SCAN_MILLIS = "last_scan_millis";
    private final ExecutorService exec = Executors.newSingleThreadExecutor();
    private java.util.concurrent.Future<?> scanTask;
    private volatile boolean cancelRequested;
    private final Handler progressHandler = new Handler(Looper.getMainLooper());
    private volatile long phaseStartedAt;
    private volatile String currentPhase = "Preparando inventário…";
    private final Runnable phaseTicker = new Runnable() {
        @Override public void run() {
            if (progressContainer != null && progressContainer.getVisibility() == View.VISIBLE) {
                long elapsed = Math.max(0L, (System.nanoTime() - phaseStartedAt) / 1_000_000_000L);
                lastScan.setText("VERIFICAÇÃO EM ANDAMENTO • " + currentPhase + " • " + elapsed + "s nesta fase");
                progressHandler.postDelayed(this, 1000L);
            }
        }
    };

    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        score = findViewById(R.id.score);
        summary = findViewById(R.id.summary);
        report = findViewById(R.id.report);
        lastScan = findViewById(R.id.last_scan);
        nextAction = findViewById(R.id.next_action);
        coverageHint = findViewById(R.id.coverage_hint);
        countCritical = findViewById(R.id.count_critical);
        countHigh = findViewById(R.id.count_high);
        countMedium = findViewById(R.id.count_medium);
        countLow = findViewById(R.id.count_low);
        progressContainer = findViewById(R.id.progress_container);
        scanProgress = findViewById(R.id.scan_progress);
        scanProgressStage = findViewById(R.id.scan_progress_stage);
        scan = findViewById(R.id.scan);
        cancelScan = findViewById(R.id.cancel_scan);
        remediation = findViewById(R.id.remediation);
        securitySettings = findViewById(R.id.settings);
        share = findViewById(R.id.share);
        copy = findViewById(R.id.copy);

        scan.setOnClickListener(v -> startScan());
        cancelScan.setOnClickListener(v -> cancelActiveScan());
        remediation.setOnClickListener(v -> showRemediationCenter());
        securitySettings.setOnClickListener(v -> openSecuritySettings());
        share.setOnClickListener(v -> shareReport());
        copy.setOnClickListener(v -> copyReport());
        restoreLastScanTimestamp();
        share.setEnabled(false);
        copy.setEnabled(false);
        summary.setMovementMethod(android.text.method.LinkMovementMethod.getInstance());
    }

    @Override protected void onDestroy() {
        progressHandler.removeCallbacks(phaseTicker);
        exec.shutdownNow();
        super.onDestroy();
    }

    private void startScan() {
        cancelRequested = false;
        cancelScan.setVisibility(View.VISIBLE);
        cancelScan.setEnabled(true);
        scan.setEnabled(false);
        scan.setText("VERIFICANDO…");
        share.setEnabled(false);
        copy.setEnabled(false);
        remediation.setEnabled(false);
        progressContainer.setVisibility(View.VISIBLE);
        scanProgress.setPercent(0);
        currentPhase = "Preparando inventário…";
        phaseStartedAt = System.nanoTime();
        scanProgressStage.setText(currentPhase);
        progressHandler.removeCallbacks(phaseTicker);
        progressHandler.post(phaseTicker);
        score.setText("Verificando…");
        summary.setText("Analisando indicadores locais do Android");
        lastScan.setText("VERIFICAÇÃO EM ANDAMENTO");
        nextAction.setText("Aguarde enquanto o DarkShield analisa o dispositivo.");
        report.setText("");
        countCritical.setText("CRÍTICO\n0");
        countHigh.setText("ALTO\n0");
        countMedium.setText("MÉDIO\n0");
        countLow.setText("BAIXO\n0");

        final long startedAt = System.nanoTime();
        scanTimingTracker = new ScanTimingTracker();
        scanTask = exec.submit(() -> {
            try {
                List<ScanFinding> findings = new SecurityScanner(this).scan(
                        new SecurityScanner.ProgressListener() {
                            @Override public void onProgress(int completed, int total, String packageName) {
                                int percent = total <= 0 ? 5 : 5 + (int) ((completed * 80L) / total);
                                String label = packageName == null || packageName.isEmpty()
                                        ? "Preparando inventário…"
                                        : packageName;
                                runOnUiThread(() -> {
                                    if (isFinishing() || isDestroyed()) return;
                                    scanProgress.setPercent(percent);
                                    scanProgressStage.setText(label);
                                    summary.setText("Analisando aplicativo " + completed + "/" + total
                                            + "\n" + label);
                                    lastScan.setText("VERIFICAÇÃO EM ANDAMENTO • " + percent + "%");
                                });
                            }

                            @Override public void onPackageStart(int completed, int total, String packageName) {
                                runOnUiThread(() -> {
                                    if (isFinishing() || isDestroyed()) return;
                                    currentPhase = "Analisando aplicativo";
                                    phaseStartedAt = System.nanoTime();
                                    scanProgressStage.setText(packageName == null ? "Aplicativo" : packageName);
                                    summary.setText("Analisando aplicativo " + (completed + 1) + "/" + total
                                            + "\n" + (packageName == null ? "pacote desconhecido" : packageName));
                                    lastScan.setText("VERIFICAÇÃO EM ANDAMENTO • aplicativo " + (completed + 1) + "/" + total);
                                });
                            }

                            @Override public void onPackageComplete(int completed, int total, String packageName, long durationMillis,
                                                                    com.darkshield.security.analysis.StaticApkAnalyzer.TimingSnapshot timing) {
                                scanTimingTracker.record(packageName, durationMillis, timing);
                                final String pkg = packageName == null || packageName.isEmpty() ? "pacote desconhecido" : packageName;
                                final String duration = formatDuration(durationMillis);
                                runOnUiThread(() -> {
                                    if (isFinishing() || isDestroyed()) return;
                                    lastScan.setText("VERIFICAÇÃO EM ANDAMENTO • " + completed + "/" + total
                                            + " • último aplicativo: " + pkg + " • " + duration);
                                });
                            }

                            @Override public void onStage(String stage) {
                                runOnUiThread(() -> {
                                    if (isFinishing() || isDestroyed()) return;
                                    currentPhase = stage;
                                    phaseStartedAt = System.nanoTime();
                                    scanProgressStage.setText(stage);
                                    summary.setText(stage);
                                    lastScan.setText("VERIFICAÇÃO EM ANDAMENTO • " + stage);
                                });
                            }
                        });
                long durationMillis = Math.max(0L, (System.nanoTime() - startedAt) / 1_000_000L);
                runOnUiThread(() -> finishScan(findings, durationMillis));
            } catch (Exception e) {
                long durationMillis = Math.max(0L, (System.nanoTime() - startedAt) / 1_000_000L);
                runOnUiThread(() -> finishScanError(e, durationMillis));
            }
        });
    }


    private int progressForStage(String stage) {
        if (stage == null) return 5;
        if (stage.contains("Preparando")) return 5;
        if (stage.contains("Analisando aplicativos")) return 10;
        if (stage.contains("serviços especiais")) return 88;
        if (stage.contains("Correlacionando")) return 92;
        if (stage.contains("integridade")) return 95;
        if (stage.contains("rede")) return 98;
        if (stage.contains("Finalizando")) return 99;
        return 85;
    }

    private void cancelActiveScan() {
        if (scanTask == null || scanTask.isDone()) return;
        cancelRequested = true;
        cancelScan.setEnabled(false);
        cancelScan.setText("CANCELANDO…");
        scanTask.cancel(true);
    }

    private void finishScan(List<ScanFinding> findings, long durationMillis) {
        // Cancellation can race with the worker finishing. Never publish a completed report
        // after the user has already requested cancellation.
        if (cancelRequested) {
            finishScanError(new InterruptedException("Verificação cancelada pelo usuário."), durationMillis);
            return;
        }
        if (isFinishing() || isDestroyed()) return;
        ScanReport scanReport = new ScanReport(findings);
        lastScanReport = scanReport;
        int critical = scanReport.count(ScanFinding.Level.CRITICAL);
        int high = scanReport.count(ScanFinding.Level.HIGH);
        int medium = scanReport.count(ScanFinding.Level.MEDIUM);
        int low = scanReport.count(ScanFinding.Level.LOW);
        int risk = scanReport.getScore();
        countCritical.setText("CRÍTICO\n" + critical);
        countHigh.setText("ALTO\n" + high);
        countMedium.setText("MÉDIO\n" + medium);
        countLow.setText("BAIXO\n" + low);
        updateSeverityAccessibility(countCritical, "crítico", critical);
        updateSeverityAccessibility(countHigh, "alto", high);
        updateSeverityAccessibility(countMedium, "médio", medium);
        updateSeverityAccessibility(countLow, "baixo", low);
        String status = scanReport.getStatus();
        coverageHint.setText("Cobertura desta verificação: " + findings.size()
                + " registro(s) técnico(s) • " + scanReport.countRequiringReview()
                + " item(ns) para revisão • " + scanReport.packageSummaries().size()
                + " pacote(s) com sinais.");
        String details = scanReport.details();
        String informational = scanReport.informationalDetails();
        score.setText(status + "  •  " + risk + "/100");
        score.setTextColor(risk >= 70
                ? 0xFFFF6B6B
                : risk >= 40 ? 0xFFFFC857 : 0xFF66E3A4);
        String packageSummary = scanReport.packageSummary();
        ScanTimingTracker.Entry slowestPackage = scanTimingTracker == null ? null : scanTimingTracker.slowest();
        String timingSummary = slowestPackage == null
                ? ""
                : "\nDiagnóstico de desempenho: " + slowestPackage.packageName
                        + " levou " + formatDuration(slowestPackage.durationMillis) + " na análise profunda."
                        + formatStaticTiming(slowestPackage.staticApkTiming);
        String summaryText =
                "Crítico: " + critical + "   Alto: " + high
                        + "   Médio: " + medium + "   Baixo: " + low
                        + "\n" + scanReport.countRequiringReview()
                        + " item(ns) exigem revisão; " + findings.size() + " registro(s) no total.\n"
                        + "Pontos heurísticos: " + scanReport.getRawPoints()
                        + " → score exibido: " + risk + "/100."
                        + timingSummary + "\n\n";
        SpannableStringBuilder summaryBuilder = new SpannableStringBuilder(summaryText);
        if (!packageSummary.isEmpty()) {
            int packageStart = summaryBuilder.length();
            summaryBuilder.append("Pacotes com sinais para revisão:\n").append(packageSummary);
            summaryBuilder.append("\n\n");
            addPackageLinks(summaryBuilder, packageStart, scanReport);
        }
        summaryBuilder.append(
                "A pontuação é heurística: um achado não prova invasão ou malware."
        );
        summary.setText(summaryBuilder, TextView.BufferType.SPANNABLE);

        lastReport = buildShareReport(scanReport, status, risk, details, informational);
        report.setText(renderReportDetails(details, informational));
        String timestamp = new SimpleDateFormat("dd/MM/yyyy • HH:mm", Locale.getDefault())
                .format(new Date());
        long completedAt = System.currentTimeMillis();
        saveLastScanTimestamp(completedAt);
        lastScan.setText("Última verificação: " + timestamp + " • duração: " + formatDuration(durationMillis));
        nextAction.setText(risk >= 70
                ? "Próximo passo: revise primeiro os itens críticos e altos abaixo."
                : risk >= 40
                        ? "Próximo passo: revise os aplicativos e configurações sensíveis listados abaixo."
                        : "Próximo passo: mantenha o Android e seus aplicativos atualizados e faça verificações periódicas.");

        scanProgress.setPercent(100);
        scanProgressStage.setText("Verificação concluída");
        progressContainer.setVisibility(View.GONE);
        progressHandler.removeCallbacks(phaseTicker);
        cancelScan.setVisibility(View.GONE);
        cancelScan.setEnabled(false);
        cancelScan.setText("CANCELAR VERIFICAÇÃO");
        scan.setText("VERIFICAR NOVAMENTE");
        scan.setEnabled(true);
        share.setEnabled(true);
        copy.setEnabled(true);
        remediation.setEnabled(!RemediationPlanner.plan(findings).isEmpty());
    }

    private void showRemediationCenter() {
        if (lastScanReport == null) {
            Toast.makeText(this, "Execute uma verificação primeiro.", Toast.LENGTH_SHORT).show();
            return;
        }

        List<RemediationPlanner.Action> actions =
                RemediationPlanner.plan(lastScanReport.getFindings());
        if (actions.isEmpty()) {
            Toast.makeText(this, "Nenhuma correção segura foi identificada.", Toast.LENGTH_SHORT).show();
            return;
        }

        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        LinearLayout container = new LinearLayout(this);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setPadding(pad, pad / 2, pad, pad / 2);

        TextView intro = new TextView(this);
        intro.setText("Selecione as providências desejadas. O DarkShield automatiza o encaminhamento seguro; "
                + "quando o Android protege uma alteração, a confirmação final continua sendo feita na tela oficial do sistema.");
        intro.setTextSize(13);
        intro.setTextColor(0xFFB8BECC);
        intro.setPadding(0, 0, 0, pad / 2);
        container.addView(intro);

        List<CheckBox> selections = new ArrayList<>();
        for (RemediationPlanner.Action action : actions) {
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.VERTICAL);
            row.setPadding(0, pad / 3, 0, pad / 3);

            CheckBox select = new CheckBox(this);
            select.setText(action.title);
            select.setTextSize(14);
            select.setTextColor(0xFFFFFFFF);
            select.setTag(action);
            selections.add(select);
            row.addView(select);

            TextView reason = new TextView(this);
            reason.setText(action.reason);
            reason.setTextSize(12);
            reason.setTextColor(0xFFB8BECC);
            reason.setPadding(0, 0, 0, pad / 4);
            row.addView(reason);

            Button open = new Button(this);
            open.setText(action.uninstallCandidate
                    ? "REVISAR / DESINSTALAR NO ANDROID"
                    : "ABRIR CORREÇÃO");
            open.setOnClickListener(v -> openRemediation(action));
            row.addView(open);
            container.addView(row);
        }

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(container);
        int maxHeight = (int) (getResources().getDisplayMetrics().heightPixels * 0.68f);
        scroll.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, maxHeight));

        android.app.AlertDialog dialog = new android.app.AlertDialog.Builder(this)
                .setTitle("Central de correções seguras")
                .setView(scroll)
                .setNegativeButton("FECHAR", null)
                .setPositiveButton("CORRIGIR SELECIONADO", null)
                .create();

        dialog.setOnShowListener(ignored -> dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE)
                .setOnClickListener(v -> {
                    List<RemediationPlanner.Action> selected = new ArrayList<>();
                    for (CheckBox box : selections) {
                        if (box.isChecked()) {
                            selected.add((RemediationPlanner.Action) box.getTag());
                        }
                    }
                    if (selected.isEmpty()) {
                        Toast.makeText(this, "Selecione pelo menos uma providência.", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    if (selected.size() > 1) {
                        Toast.makeText(this,
                                "Abrindo a primeira correção. Volte ao DarkShield para continuar as demais.",
                                Toast.LENGTH_LONG).show();
                    }
                    openRemediation(selected.get(0));
                }));
        dialog.show();
    }

    private void openRemediation(RemediationPlanner.Action action) {
        Intent intent;
        Uri packageUri = Uri.parse("package:" + action.packageName);
        switch (action.kind) {
            case ACCESSIBILITY:
                intent = new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
                break;
            case NOTIFICATIONS:
                intent = new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS);
                break;
            case OVERLAY:
                intent = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, packageUri);
                break;
            case WRITE_SETTINGS:
                intent = new Intent(Settings.ACTION_MANAGE_WRITE_SETTINGS, packageUri);
                break;
            case UNKNOWN_SOURCES:
                intent = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, packageUri);
                break;
            case USAGE_ACCESS:
                intent = new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS);
                break;
            case SECURITY:
                intent = new Intent(Settings.ACTION_SECURITY_SETTINGS);
                break;
            default:
                intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, packageUri);
                break;
        }

        try {
            startActivity(intent);
        } catch (Exception first) {
            try {
                startActivity(new Intent(
                        Settings.ACTION_APPLICATION_DETAILS_SETTINGS, packageUri));
            } catch (Exception second) {
                Toast.makeText(this,
                        "O Android não disponibilizou a tela de correção para este item.",
                        Toast.LENGTH_SHORT).show();
            }
        }
    }

    private void saveLastScanTimestamp(long timestamp) {
        try {
            getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                    .edit()
                    .putLong(KEY_LAST_SCAN_MILLIS, timestamp)
                    .apply();
        } catch (Exception ignored) {
            // A interface continua funcionando mesmo se a persistência local falhar.
        }
    }

    private void restoreLastScanTimestamp() {
        try {
            long timestamp = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                    .getLong(KEY_LAST_SCAN_MILLIS, 0L);
            if (timestamp <= 0L) return;
            String formatted = new SimpleDateFormat("dd/MM/yyyy • HH:mm", Locale.getDefault())
                    .format(new Date(timestamp));
            lastScan.setText("Última verificação salva: " + formatted);
            nextAction.setText("Próximo passo: execute uma nova verificação para atualizar o estado do dispositivo.");
        } catch (Exception ignored) {
            // Não bloquear a tela inicial por falha de leitura das preferências.
        }
    }

    private String formatDuration(long durationMillis) {
        if (durationMillis < 1000L) return durationMillis + " ms";
        return String.format(Locale.getDefault(), "%.1f s", durationMillis / 1000.0);
    }

    private void updateSeverityAccessibility(TextView view, String severity, int count) {
        view.setContentDescription("Quantidade de achados " + severity + ": " + count);
    }

    private void addPackageLinks(
            SpannableStringBuilder builder, int packageStart, ScanReport scanReport) {
        int sectionEnd = builder.length();
        String rendered = builder.toString();
        for (ScanReport.PackageSummary item : scanReport.packageSummaries()) {
            if (item.packageName == null || item.packageName.trim().isEmpty()) continue;
            String token = "• " + item.packageName + " •";
            int tokenStart = rendered.indexOf(token, packageStart);
            if (tokenStart < 0 || tokenStart >= sectionEnd) continue;
            int from = tokenStart + 2;
            int to = from + item.packageName.length();
            final String packageName = item.packageName;
            builder.setSpan(new ClickableSpan() {
                @Override public void onClick(View widget) {
                    try {
                        widget.getContext().startActivity(new Intent(
                                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                Uri.parse("package:" + packageName)));
                    } catch (Exception ignored) {
                        Toast.makeText(widget.getContext(),
                                "Não foi possível abrir os detalhes deste aplicativo.",
                                Toast.LENGTH_SHORT).show();
                    }
                }
            }, from, to, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
    }

    private String formatStaticTiming(com.darkshield.security.analysis.StaticApkAnalyzer.TimingSnapshot timing) {
        if (timing == null) return "";
        if (timing.cacheHit) return " Cache APK reutilizado.";
        return " (ZIP: " + formatDuration(timing.zipMillis)
                + "; SHA-256: " + formatDuration(timing.hashMillis)
                + "; amostra: " + timing.contentBytesScanned + " B).";
    }

    private void finishScanError(Exception e, long durationMillis) {
        if (isFinishing() || isDestroyed()) return;
        if (cancelRequested) {
            progressHandler.removeCallbacks(phaseTicker);
            progressContainer.setVisibility(View.GONE);
            cancelScan.setVisibility(View.GONE);
            cancelScan.setEnabled(false);
            cancelScan.setText("CANCELAR VERIFICAÇÃO");
            scan.setText("VERIFICAR NOVAMENTE");
            scan.setEnabled(true);
            share.setEnabled(false);
            copy.setEnabled(false);
            remediation.setEnabled(false);
            score.setText("VERIFICAÇÃO CANCELADA");
            lastScan.setText("Verificação cancelada • duração: " + formatDuration(durationMillis));
            nextAction.setText("Próximo passo: execute uma nova verificação quando quiser.");
            summary.setText("A verificação foi interrompida pelo usuário. Nenhum resultado parcial foi apresentado como diagnóstico.");
            report.setText("A verificação foi cancelada antes da conclusão.");
            cancelRequested = false;
            return;
        }
        progressContainer.setVisibility(View.GONE);
        scanProgress.setPercent(0);
        scanProgressStage.setText("Preparando inventário…");
        scan.setText("TENTAR NOVAMENTE");
        scan.setEnabled(true);
        share.setEnabled(false);
        copy.setEnabled(false);
        remediation.setEnabled(false);
        lastReport = "";
        lastScanReport = null;
        countCritical.setText("CRÍTICO\n0");
        countHigh.setText("ALTO\n0");
        countMedium.setText("MÉDIO\n0");
        countLow.setText("BAIXO\n0");
        updateSeverityAccessibility(countCritical, "crítico", 0);
        updateSeverityAccessibility(countHigh, "alto", 0);
        updateSeverityAccessibility(countMedium, "médio", 0);
        updateSeverityAccessibility(countLow, "baixo", 0);
        coverageHint.setText("Cobertura desta verificação: indisponível porque a análise não foi concluída.");
        score.setText("VERIFICAÇÃO NÃO CONCLUÍDA");
        lastScan.setText("Última verificação: falhou • duração: " + formatDuration(durationMillis));
        nextAction.setText("Próximo passo: tente a verificação novamente. O erro, por si só, não indica comprometimento.");
        summary.setText(
                "A verificação não foi concluída. Nenhum resultado desta tentativa deve ser interpretado como avaliação do dispositivo."
        );
        String message = e.getMessage();
        report.setText(
                message == null || message.trim().isEmpty()
                        ? "Erro inesperado durante a verificação."
                        : "Erro durante a verificação:\n" + message
        );
        Toast.makeText(this, "A verificação não foi concluída.", Toast.LENGTH_SHORT).show();
    }

    private String renderReportDetails(String details, String informational) {
        if (details.isEmpty() && informational.isEmpty()) {
            return "Nenhum indicador que exija revisão imediata foi encontrado.";
        }
        StringBuilder out = new StringBuilder();
        if (!details.isEmpty()) out.append(details);
        if (!informational.isEmpty()) {
            if (out.length() > 0) out.append("\n\n");
            out.append("INFORMAÇÕES TÉCNICAS\n\n").append(informational);
        }
        return out.toString();
    }

    private String buildShareReport(
            ScanReport report, String status, int risk, String details, String informational) {
        StringBuilder b = new StringBuilder();
        b.append("DarkShield — Relatório de segurança\n");
        b.append("Status: ").append(status).append("\n");
        b.append("Score heurístico: ").append(risk).append("/100\n");
        b.append("Pontos heurísticos brutos: ").append(report.getRawPoints()).append("\n");
        b.append("Crítico: ").append(report.count(ScanFinding.Level.CRITICAL))
                .append(" | Alto: ").append(report.count(ScanFinding.Level.HIGH))
                .append(" | Médio: ").append(report.count(ScanFinding.Level.MEDIUM))
                .append(" | Baixo: ").append(report.count(ScanFinding.Level.LOW)).append("\n");
        b.append("Itens para revisão: ").append(report.countRequiringReview()).append("\n");
        b.append("Registros totais: ").append(report.getFindings().size()).append("\n");
        String packageSummary = report.packageSummary();
        if (!packageSummary.isEmpty()) {
            b.append("\nPacotes com sinais para revisão:\n").append(packageSummary).append("\n");
        }
        b.append("\n").append(renderReportDetails(details, informational)).append("\n");
        b.append(
                "Nota: indicadores heurísticos não constituem prova automática "
                        + "de malware ou invasão.\n"
        );
        return b.toString();
    }

    private void shareReport() {
        if (lastReport.isEmpty()) {
            Toast.makeText(this, "Execute uma verificação primeiro.", Toast.LENGTH_SHORT).show();
            return;
        }

        Intent send = new Intent(Intent.ACTION_SEND);
        send.setType("text/plain");
        send.putExtra(Intent.EXTRA_SUBJECT, "DarkShield — Relatório de segurança");
        send.putExtra(Intent.EXTRA_TEXT, lastReport);
        try {
            startActivity(Intent.createChooser(send, "Compartilhar relatório"));
        } catch (Exception e) {
            Toast.makeText(this,
                    "Não foi possível abrir um aplicativo para compartilhar o relatório.",
                    Toast.LENGTH_SHORT).show();
        }
    }

    private void copyReport() {
        if (lastReport.isEmpty()) {
            Toast.makeText(this, "Execute uma verificação primeiro.", Toast.LENGTH_SHORT).show();
            return;
        }

        ClipboardManager clipboard =
                (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null) {
            Toast.makeText(this, "Não foi possível acessar a área de transferência.", Toast.LENGTH_SHORT).show();
            return;
        }

        clipboard.setPrimaryClip(ClipData.newPlainText(
                "DarkShield — Relatório de segurança", lastReport));
        Toast.makeText(this, "Relatório copiado.", Toast.LENGTH_SHORT).show();
    }

    private void openSecuritySettings() {
        try {
            startActivity(new Intent(Settings.ACTION_SECURITY_SETTINGS));
        } catch (Exception e) {
            Toast.makeText(this,
                    "Não foi possível abrir as configurações de segurança.",
                    Toast.LENGTH_SHORT).show();
        }
    }
}
