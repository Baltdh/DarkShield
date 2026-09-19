package com.darkshield.security;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.AppOpsManager;
import android.app.admin.DevicePolicyManager;
import android.app.KeyguardManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.os.Build;
import android.os.PowerManager;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.accessibility.AccessibilityManager;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.*;
import com.darkshield.security.analysis.StaticApkAnalyzer;
import com.darkshield.security.analysis.ThreatCorrelationEngine;

public final class SecurityScanner {
    private static final String[] SENSITIVE_PERMISSIONS = {
        "android.permission.READ_SMS","android.permission.RECEIVE_SMS","android.permission.SEND_SMS",
        "android.permission.READ_CALL_LOG","android.permission.WRITE_CALL_LOG","android.permission.CALL_LOG",
        "android.permission.RECORD_AUDIO","android.permission.CAMERA","android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION","android.permission.READ_CONTACTS","android.permission.WRITE_CONTACTS",
        "android.permission.SYSTEM_ALERT_WINDOW","android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.PACKAGE_USAGE_STATS","android.permission.READ_PHONE_STATE",
        "android.permission.WRITE_SETTINGS","android.permission.MANAGE_EXTERNAL_STORAGE"
    };
    private static final Set<String> REMOTE_MARKERS = new HashSet<>(Arrays.asList(
        "anydesk","teamviewer","airdroid","rustdesk","splashtop","vysor","scrcpy",
        "remotecontrol","remote support","remote desktop","remote access"
    ));
    private final Context c;
    private final PackageManager pm;
    private final AppOpsManager appOps;
    private final Map<String, ApplicationInfo> appInfoCache = new HashMap<>();

    public SecurityScanner(Context c) {
        this.c = c.getApplicationContext();
        this.pm = c.getPackageManager();
        this.appOps = (AppOpsManager) this.c.getSystemService(Context.APP_OPS_SERVICE);
    }

    public interface ProgressListener {
        void onProgress(int completed, int total, String packageName);

        default void onStage(String stage) {
        }
    }

    public List<ScanFinding> scan() {
        return scan(null);
    }

    public List<ScanFinding> scan(ProgressListener listener) {
        List<ScanFinding> out = new ArrayList<>();
        if (listener != null) listener.onStage("Preparando inventário…");
        addBaseline(out);
        List<PackageInfo> apps = getApps();
        if (apps == null) {
            if (listener != null) listener.onStage("Verificando serviços especiais…");
            out.add(new ScanFinding(
                    ScanFinding.Level.MEDIUM,
                    "Inventário de aplicativos incompleto",
                    "O Android não permitiu consultar a lista de aplicativos instalados; a verificação por pacote não pôde ser concluída.",
                    null, 3,
                    "Repita a verificação e confirme se o sistema não está restringindo a visibilidade dos pacotes"));
            checkAccessibility(out);
            checkNotificationListeners(out);
            checkDeviceAdmins(out);
            if (listener != null) listener.onStage("Correlacionando indicadores…");
            out.addAll(ThreatCorrelationEngine.correlate(out));
            if (listener != null) listener.onStage("Verificando integridade do sistema…");
            checkSystemIntegrity(out);
            if (listener != null) listener.onStage("Verificando rede…");
            checkNetworkState(out);
            if (listener != null) listener.onStage("Finalizando relatório…");
            return out;
        }
        out.add(new ScanFinding(
                ScanFinding.Level.INFO, "Aplicativos analisados",
                apps.size() + " pacote(s) visíveis para o scanner", null, 0, null));
        int total = apps.size();
        int completed = 0;
        if (listener != null) {
            listener.onStage("Analisando aplicativos…");
            listener.onProgress(0, total, null);
        }
        for (PackageInfo p : apps) {
            if (Thread.currentThread().isInterrupted()) {
                throw new IllegalStateException("A verificação foi interrompida antes de concluir.");
            }
            if (p == null) {
                completed++;
                if (listener != null) listener.onProgress(completed, total, null);
                continue;
            }
            try {
                inspectApp(p, out);
            } catch (Exception e) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new IllegalStateException("A verificação foi interrompida.", e);
                }
                String packageName = p.packageName;
                out.add(new ScanFinding(
                        ScanFinding.Level.LOW,
                        "Falha ao analisar aplicativo",
                        "O scanner não conseguiu concluir a análise deste pacote; os demais aplicativos continuarão sendo analisados",
                        packageName, 1,
                        "Revise manualmente o aplicativo se você não o reconhecer"));
            }
            completed++;
            if (listener != null) {
                listener.onProgress(completed, total, p.packageName);
            }
        }
        if (listener != null) listener.onStage("Verificando serviços especiais…");
        checkAccessibility(out);
        checkNotificationListeners(out);
        checkDeviceAdmins(out);
        if (listener != null) listener.onStage("Correlacionando indicadores…");
        out.addAll(ThreatCorrelationEngine.correlate(out));
        if (listener != null) listener.onStage("Verificando integridade do sistema…");
        checkSystemIntegrity(out);
        if (listener != null) listener.onStage("Verificando rede…");
        checkNetworkState(out);
        if (listener != null) listener.onStage("Finalizando relatório…");
        return out;
    }

    private List<PackageInfo> getApps() {
        int flags = PackageManager.GET_PERMISSIONS
                | PackageManager.GET_SERVICES
                | PackageManager.GET_RECEIVERS
                | PackageManager.GET_PROVIDERS
                | PackageManager.GET_ACTIVITIES;
        if (Build.VERSION.SDK_INT >= 28) flags |= PackageManager.GET_SIGNING_CERTIFICATES;
        else flags |= PackageManager.GET_SIGNATURES;
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                return pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags));
            }
            return pm.getInstalledPackages(flags);
        } catch (Exception e) {
            return null;
        }
    }
