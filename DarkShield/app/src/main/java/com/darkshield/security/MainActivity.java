package com.darkshield.security;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
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
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends android.app.Activity {
    private TextView score, summary, report, lastScan;
    private ProgressBar progress;
    private Button scan, securitySettings, share, copy;
    private String lastReport = "";
    private final ExecutorService exec = Executors.newSingleThreadExecutor();

    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        score = findViewById(R.id.score);
        summary = findViewById(R.id.summary);
        report = findViewById(R.id.report);
        lastScan = findViewById(R.id.last_scan);
        progress = findViewById(R.id.progress);
        scan = findViewById(R.id.scan);
        securitySettings = findViewById(R.id.settings);
        share = findViewById(R.id.share);
        copy = findViewById(R.id.copy);

        scan.setOnClickListener(v -> startScan());
        securitySettings.setOnClickListener(v -> openSecuritySettings());
        share.setOnClickListener(v -> shareReport());
        copy.setOnClickListener(v -> copyReport());
        share.setEnabled(false);
        copy.setEnabled(false);
        summary.setMovementMethod(android.text.method.LinkMovementMethod.getInstance());
    }

    private void startScan() {
        scan.setEnabled(false);
        scan.setText("VERIFICANDO…");
        share.setEnabled(false);
        copy.setEnabled(false);
        progress.setVisibility(View.VISIBLE);
        score.setText("Verificando…");
        summary.setText("Analisando indicadores locais do Android");
        lastScan.setText("VERIFICAÇÃO EM ANDAMENTO");
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
        if (isFinishing() || isDestroyed()) return;
        ScanReport scanReport = new ScanReport(findings);
        int critical = scanReport.count(ScanFinding.Level.CRITICAL);
        int high = scanReport.count(ScanFinding.Level.HIGH);
        int medium = scanReport.count(ScanFinding.Level.MEDIUM);
        int low = scanReport.count(ScanFinding.Level.LOW);
        int risk = scanReport.getScore();
        String status = scanReport.getStatus();
        String details = scanReport.details();
        String informational = scanReport.informationalDetails();
        score.setText(status + "  •  " + risk + "/100");
        score.setTextColor(risk >= 70
                ? 0xFFFF6B6B
                : risk >= 40 ? 0xFFFFC857 : 0xFF66E3A4);
        String packageSummary = scanReport.packageSummary();
        String summaryText =
                "Crítico: " + critical + "   Alto: " + high
                        + "   Médio: " + medium + "   Baixo: " + low
                        + "\n" + scanReport.countRequiringReview()
                        + " item(ns) exigem revisão; " + findings.size() + " registro(s) no total.\n"
                        + "Pontos heurísticos: " + scanReport.getRawPoints()
                        + " → score exibido: " + risk + "/100.\n\n";
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
        lastScan.setText("Última verificação: " + timestamp);

        progress.setVisibility(View.GONE);
        scan.setText("VERIFICAR NOVAMENTE");
        scan.setEnabled(true);
        share.setEnabled(true);
        copy.setEnabled(true);
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

    private void finishScanError(Exception e) {
        if (isFinishing() || isDestroyed()) return;
        progress.setVisibility(View.GONE);
        scan.setText("TENTAR NOVAMENTE");
        scan.setEnabled(true);
        share.setEnabled(false);
        copy.setEnabled(false);
        lastReport = "";
        score.setText("VERIFICAÇÃO NÃO CONCLUÍDA");
        lastScan.setText("Última verificação: falhou");
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
            Toast.makeText(this, "Não foi possível acessar a área de transferência.",
                    Toast.LENGTH_SHORT).show();
            return;
        }

        try {
            clipboard.setPrimaryClip(
                    ClipData.newPlainText("Relatório DarkShield", lastReport));
            Toast.makeText(this, "Relatório copiado.", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this, "Não foi possível copiar o relatório.",
                    Toast.LENGTH_SHORT).show();
        }
    }

    private void openSecuritySettings() {
        try {
            startActivity(new Intent(Settings.ACTION_SECURITY_SETTINGS));
        } catch (Exception e) {
            try {
                startActivity(new Intent(Settings.ACTION_SETTINGS));
            } catch (Exception ignored) {
                Toast.makeText(this,
                        "Não foi possível abrir as configurações de segurança.",
                        Toast.LENGTH_SHORT).show();
            }
        }
    }

    @Override protected void onDestroy() {
        exec.shutdownNow();
        super.onDestroy();
    }
}
