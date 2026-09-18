package com.darkshield.security;

import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
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
        int critical = 0, high = 0, medium = 0, low = 0;
        StringBuilder sb = new StringBuilder();

        for (ScanFinding x : findings) {
            if (x == null) continue;
            if (x.level == ScanFinding.Level.CRITICAL) critical++;
            else if (x.level == ScanFinding.Level.HIGH) high++;
            else if (x.level == ScanFinding.Level.MEDIUM) medium++;
            else if (x.level == ScanFinding.Level.LOW) low++;
            if (x.level != ScanFinding.Level.INFO) {
                sb.append(x.line()).append("\n\n");
            }
        }

        int risk = RiskCalculator.score(findings);
        String status = RiskCalculator.status(findings);
        score.setText(status + "  •  " + risk + "/100");
        summary.setText(
                "Crítico: " + critical + "   Alto: " + high
                        + "   Médio: " + medium + "   Baixo: " + low
                        + "\n" + findings.size() + " achado(s) registrados.\n\n"
                        + "A pontuação é heurística: um achado não prova invasão ou malware."
        );

        lastReport = buildShareReport(findings, status, risk, sb.toString());
        report.setText(
                sb.length() == 0
                        ? "Nenhum indicador que exija revisão imediata foi encontrado."
                        : sb.toString()
        );

        progress.setVisibility(View.GONE);
        scan.setEnabled(true);
        share.setEnabled(true);
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
            List<ScanFinding> findings, String status, int risk, String details) {
        StringBuilder b = new StringBuilder();
        b.append("DarkShield — Relatório de segurança\n");
        b.append("Status: ").append(status).append("\n");
        b.append("Score heurístico: ").append(risk).append("/100\n");
        b.append("Achados registrados: ").append(findings.size()).append("\n\n");
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
