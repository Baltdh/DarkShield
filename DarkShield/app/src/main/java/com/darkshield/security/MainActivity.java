package com.darkshield.security;

import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.net.Uri;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ClickableSpan;
import android.view.View;
import android.widget.Toast;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends android.app.Activity {
    private TextView score, summary, report;
    private ProgressBar progress;
    private Button scan, securitySettings, share;
    private String lastReport = "";
    private final ExecutorService exec = Executors.newSingleThreadExecutor();

    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        score = findViewById(R.id.score);
        summary = findViewById(R.id.summary);
        report = findViewById(R.id.report);
        progress = findViewById(R.id.progress);
        scan = findViewById(R.id.scan);
        securitySettings = findViewById(R.id.settings);
        share = findViewById(R.id.share);

        scan.setOnClickListener(v -> startScan());
        securitySettings.setOnClickListener(v -> openSecuritySettings());
        share.setOnClickListener(v -> shareReport());
        share.setEnabled(false);
        summary.setMovementMethod(android.text.method.LinkMovementMethod.getInstance());
    }

    private void startScan() {
        scan.setEnabled(false);
        share.setEnabled(false);
        progress.setVisibility(View.VISIBLE);
        score.setText("Verificando…");
        summary.setText("Analisando indicadores locais do Android");
        report.setText("");

        exec.submit(() -> {
            try {
                List<ScanFinding> findings = new SecurityScanner(this).scan();
                runOnUiThread(() -> finishScan(findings));
            } catch (Exception e) {
                runOnUiThread(() -> finishScanError(e));
            }
        });
    }

    private void finishScan(List<ScanFinding> findings) {
        ScanReport scanReport = new ScanReport(findings);
        int critical = scanReport.count(ScanFinding.Level.CRITICAL);
        int high = scanReport.count(ScanFinding.Level.HIGH);
        int medium = scanReport.count(ScanFinding.Level.MEDIUM);
        int low = scanReport.count(ScanFinding.Level.LOW);
        int risk = scanReport.getScore();
        String status = scanReport.getStatus();
        String details = scanReport.details();
        score.setText(status + "  •  " + risk + "/100");
        String packageSummary = scanReport.packageSummary();
        String summaryText =
                "Crítico: " + critical + "   Alto: " + high
                        + "   Médio: " + medium + "   Baixo: " + low
                        + "\n" + scanReport.countRequiringReview()
                        + " item(ns) exigem revisão; " + findings.size() + " registro(s) no total.\n\n";
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

        lastReport = buildShareReport(scanReport, status, risk, details);
        report.setText(
                details.isEmpty()
                        ? "Nenhum indicador que exija revisão imediata foi encontrado."
                        : details
        );

        progress.setVisibility(View.GONE);
        scan.setEnabled(true);
        share.setEnabled(true);
    }

    private void addPackageLinks(
            SpannableStringBuilder builder, int packageStart, ScanReport scanReport) {
        int sectionEnd = builder.length();
        String rendered = builder.toString();
        for (ScanReport.PackageSummary item : scanReport.packageSummaries()) {
            if (item.packageName == null || item.packageName.trim().isEmpty()) continue;
            int from = rendered.indexOf(item.packageName, packageStart);
            if (from < 0 || from >= sectionEnd) continue;
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

    private void finishScanError(Exception e) {
        progress.setVisibility(View.GONE);
        scan.setEnabled(true);
        share.setEnabled(false);
        lastReport = "";
        score.setText("VERIFICAÇÃO NÃO CONCLUÍDA");
        summary.setText(
                "O scanner encontrou um erro durante a análise. "
                        + "Isso não significa que o dispositivo esteja comprometido."
        );
        String message = e.getMessage();
        report.setText(
                message == null || message.trim().isEmpty()
                        ? "Erro inesperado durante a verificação."
                        : "Erro durante a verificação:\n" + message
        );
        Toast.makeText(this, "A verificação não foi concluída.", Toast.LENGTH_SHORT).show();
    }

    private String buildShareReport(
            ScanReport report, String status, int risk, String details) {
        StringBuilder b = new StringBuilder();
        b.append("DarkShield — Relatório de segurança\n");
        b.append("Status: ").append(status).append("\n");
        b.append("Score heurístico: ").append(risk).append("/100\n");
        b.append("Itens para revisão: ").append(report.countRequiringReview()).append("\n");
        b.append("Registros totais: ").append(report.getFindings().size()).append("\n");
        String packageSummary = report.packageSummary();
        if (!packageSummary.isEmpty()) {
            b.append("\nPacotes com sinais para revisão:\n").append(packageSummary).append("\n");
        }
        b.append("\n");
        b.append(
                details.isEmpty()
                        ? "Nenhum indicador exigindo revisão imediata.\n"
                        : details
        );
        b.append(
                "\nNota: indicadores heurísticos não constituem prova automática "
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
        startActivity(Intent.createChooser(send, "Compartilhar relatório"));
    }

    private void openSecuritySettings() {
        try {
            startActivity(new Intent(Settings.ACTION_SECURITY_SETTINGS));
        } catch (Exception e) {
            startActivity(new Intent(Settings.ACTION_SETTINGS));
        }
    }

    @Override protected void onDestroy() {
        exec.shutdownNow();
        super.onDestroy();
    }
}
