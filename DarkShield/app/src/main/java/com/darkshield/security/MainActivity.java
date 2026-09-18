package com.darkshield.security;

import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends android.app.Activity {
    private TextView score, summary, report;
    private ProgressBar progress;
    private Button scan, securitySettings;
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
        scan.setOnClickListener(v -> startScan());
        securitySettings.setOnClickListener(v -> openSecuritySettings());
    }

    private void startScan() {
        scan.setEnabled(false);
        progress.setVisibility(View.VISIBLE);
        score.setText("Verificando…");
        summary.setText("Analisando indicadores locais do Android");
        report.setText("");
        exec.submit(() -> {
            List<ScanFinding> findings = new SecurityScanner(this).scan();
            runOnUiThread(() -> finishScan(findings));
        });
    }

    private void finishScan(List<ScanFinding> findings) {
        int critical = 0, high = 0, medium = 0, low = 0, points = 0;
        StringBuilder sb = new StringBuilder();
        for (ScanFinding x : findings) {
            points += x.points;
            if (x.level == ScanFinding.Level.CRITICAL) critical++;
            else if (x.level == ScanFinding.Level.HIGH) high++;
            else if (x.level == ScanFinding.Level.MEDIUM) medium++;
            else if (x.level == ScanFinding.Level.LOW) low++;
            if (x.level != ScanFinding.Level.INFO) sb.append(x.line()).append("\n\n");
        }
        int risk = Math.min(100, points * 3);
        String status;
        if (critical > 0) status = "RISCO CRÍTICO";
        else if (high > 0) status = "RISCO ALTO";
        else if (medium > 0) status = "REVISÃO RECOMENDADA";
        else if (low > 0) status = "POUCOS INDICADORES";
        else status = "SEM INDICADORES FORTES";
        score.setText(status + "  •  " + risk + "/100");
        summary.setText("Alto: " + high + "   Médio: " + medium + "   Baixo: " + low +
                "\n" + findings.size() + " achado(s) registrados.\n\n" +
                "A pontuação é heurística: um achado não prova invasão ou malware.");
        report.setText(sb.length() == 0 ? "Nenhum indicador que exija revisão imediata foi encontrado." : sb.toString());
        progress.setVisibility(View.GONE);
        scan.setEnabled(true);
    }

    private void openSecuritySettings() {
        try { startActivity(new Intent(Settings.ACTION_SECURITY_SETTINGS)); }
        catch (Exception e) { startActivity(new Intent(Settings.ACTION_SETTINGS)); }
    }

    @Override protected void onDestroy() {
        exec.shutdownNow();
        super.onDestroy();
    }
}