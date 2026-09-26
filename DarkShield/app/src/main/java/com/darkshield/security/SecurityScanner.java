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

        /** Called immediately before an individual package enters deep inspection. */
        default void onPackageStart(int completed, int total, String packageName) {
        }

        /** Called after an individual package finishes deep inspection. */
        default void onPackageComplete(int completed, int total, String packageName, long durationMillis) {
        }

        /** Called after an individual package with static APK timing diagnostics. */
        default void onPackageComplete(int completed, int total, String packageName,
                                        long durationMillis,
                                        StaticApkAnalyzer.TimingSnapshot timing) {
            onPackageComplete(completed, total, packageName, durationMillis);
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
            long packageStartedAt = System.nanoTime();
            if (listener != null) {
                listener.onPackageStart(completed, total, p.packageName);
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
                long packageDurationMillis =
                        Math.max(0L, (System.nanoTime() - packageStartedAt) / 1_000_000L);
                listener.onPackageComplete(completed, total, p.packageName,
                        packageDurationMillis, StaticApkAnalyzer.getLastTiming());
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

    private void inspectApp(PackageInfo p, List<ScanFinding> out) {
        ApplicationInfo ai = p.applicationInfo;
        if (ai == null || c.getPackageName().equals(p.packageName)) return;

        appInfoCache.put(p.packageName, ai);
        String label = safeLabel(ai);
        String lower = (label + " " + p.packageName).toLowerCase(Locale.ROOT);
        Set<String> ps = new HashSet<>();
        if (p.requestedPermissions != null) Collections.addAll(ps, p.requestedPermissions);

        int sensitive = 0;
        for (String permission : SENSITIVE_PERMISSIONS) {
            if (isPermissionGranted(permission, p.packageName)) sensitive++;
        }

        boolean system = isSystemApp(ai);
        boolean remoteMarker = containsRemoteControlMarker(lower);
        boolean debuggable = (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        boolean overlayGranted = isPermissionGranted(
                "android.permission.SYSTEM_ALERT_WINDOW", p.packageName);

        if (overlayGranted) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW,
                    "Permissão de sobreposição concedida",
                    label, p.packageName, 2,
                    "Revisar em Configurações > Apps > Acesso especial")
                    .withTags(ScanFinding.EvidenceTag.ACTIVE_ACCESS));
        } else if (ps.contains("android.permission.SYSTEM_ALERT_WINDOW")) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO, "Sobreposição declarada",
                    "A permissão foi declarada, mas não consta como concedida",
                    p.packageName, 0, null));
        }

        if (ps.contains("android.permission.WRITE_SETTINGS")) {
            if (hasSpecialAccess("android.permission.WRITE_SETTINGS", p.packageName)) {
                out.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Acesso especial para modificar configurações",
                        "O aplicativo declarou WRITE_SETTINGS e possui a autorização especial para modificar configurações do sistema",
                        p.packageName, 3,
                        "Confirme se essa autorização é necessária e foi concedida conscientemente")
                        .withTags(ScanFinding.EvidenceTag.ACTIVE_ACCESS));
            } else {
                out.add(new ScanFinding(
                        ScanFinding.Level.INFO,
                        "Acesso especial para modificar configurações declarado",
                        "WRITE_SETTINGS foi declarado, mas a autorização especial não consta como concedida",
                        p.packageName, 0, null));
            }
        }

        if (Build.VERSION.SDK_INT >= 30
                && ps.contains("android.permission.MANAGE_EXTERNAL_STORAGE")) {
            if (hasSpecialAccess("android.permission.MANAGE_EXTERNAL_STORAGE", p.packageName)) {
                out.add(new ScanFinding(
                        ScanFinding.Level.MEDIUM,
                        "Acesso a todos os arquivos concedido",
                        "O aplicativo declarou MANAGE_EXTERNAL_STORAGE e possui Acesso a todos os arquivos",
                        p.packageName, 3,
                        "Confirme se o acesso amplo ao armazenamento é necessário e reconhecido")
                        .withTags(
                                ScanFinding.EvidenceTag.ACTIVE_ACCESS,
                                ScanFinding.EvidenceTag.SENSITIVE_DATA));
            } else {
                out.add(new ScanFinding(
                        ScanFinding.Level.INFO,
                        "Acesso a todos os arquivos declarado",
                        "MANAGE_EXTERNAL_STORAGE foi declarado, mas o acesso especial não consta como concedido",
                        p.packageName, 0, null));
            }
        }

        int mediaCount = 0;
        if (isPermissionGranted("android.permission.RECORD_AUDIO", p.packageName)) mediaCount++;
        if (isPermissionGranted("android.permission.CAMERA", p.packageName)) mediaCount++;
        if (mediaCount > 0) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW, "Acesso a microfone/câmera",
                    label + " solicita " + mediaCount + " recurso(s) de áudio/vídeo",
                    p.packageName, 1, "Confirme se essa função é necessária")
                    .withTags(ScanFinding.EvidenceTag.SENSITIVE_DATA));
        }

        if (isPermissionGranted("android.permission.READ_SMS", p.packageName)
                || isPermissionGranted("android.permission.RECEIVE_SMS", p.packageName)
                || isPermissionGranted("android.permission.SEND_SMS", p.packageName)) {
            out.add(new ScanFinding(
                    ScanFinding.Level.MEDIUM, "Acesso a SMS",
                    "O aplicativo possui acesso operacional a mensagens SMS",
                    p.packageName, 4, "Revisar a permissão e a finalidade do aplicativo")
                    .withTags(ScanFinding.EvidenceTag.SENSITIVE_DATA));
        }

        if (isPermissionGranted("android.permission.READ_CALL_LOG", p.packageName)
                || isPermissionGranted("android.permission.WRITE_CALL_LOG", p.packageName)) {
            out.add(new ScanFinding(
                    ScanFinding.Level.MEDIUM, "Acesso ao histórico de chamadas",
                    "O aplicativo possui acesso operacional ao registro de chamadas",
                    p.packageName, 4, "Revise a permissão caso a função não exija chamadas")
                    .withTags(ScanFinding.EvidenceTag.SENSITIVE_DATA));
        }

        boolean contacts = isPermissionGranted("android.permission.READ_CONTACTS", p.packageName)
                || isPermissionGranted("android.permission.WRITE_CONTACTS", p.packageName);
        if (contacts) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO, "Acesso a contatos",
                    "O aplicativo possui acesso operacional à agenda de contatos",
                    p.packageName, 0,
                    "Confirme se a função do aplicativo realmente precisa dos seus contatos")
                    .withTags(ScanFinding.EvidenceTag.SENSITIVE_DATA));
        }

        boolean location = isPermissionGranted("android.permission.ACCESS_FINE_LOCATION", p.packageName)
                || isPermissionGranted("android.permission.ACCESS_COARSE_LOCATION", p.packageName);
        if (location) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO, "Acesso à localização",
                    "O aplicativo possui acesso operacional à localização do dispositivo",
                    p.packageName, 0,
                    "Revise a permissão e prefira localização aproximada quando suficiente")
                    .withTags(ScanFinding.EvidenceTag.SENSITIVE_DATA));
        }

        if (isPermissionGranted("android.permission.READ_PHONE_STATE", p.packageName)) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO, "Acesso ao estado do telefone",
                    "O aplicativo possui acesso operacional a informações do estado da telefonia",
                    p.packageName, 0,
                    "Confirme se essa permissão é necessária para a função esperada")
                    .withTags(ScanFinding.EvidenceTag.SENSITIVE_DATA));
        }

        if (isPermissionGranted("android.permission.PACKAGE_USAGE_STATS", p.packageName)) {
            out.add(new ScanFinding(
                    ScanFinding.Level.MEDIUM, "Acesso aos dados de uso",
                    "O aplicativo possui acesso operacional às estatísticas de uso de outros aplicativos e do dispositivo",
                    p.packageName, 3,
                    "Revise o acesso em Configurações > Acesso especial > Acesso aos dados de uso")
                    .withTags(
                            ScanFinding.EvidenceTag.ACTIVE_ACCESS,
                            ScanFinding.EvidenceTag.SENSITIVE_DATA));
        }

        if (!system && ps.contains("android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS")) {
            boolean exempt = isIgnoringBatteryOptimizations(p.packageName);
            ScanFinding batteryFinding = new ScanFinding(
                    exempt ? ScanFinding.Level.MEDIUM : ScanFinding.Level.INFO,
                    exempt ? "Exceção de otimização de bateria ativa"
                           : "Exceção de otimização de bateria declarada",
                    exempt
                            ? "O aplicativo pode pedir para permanecer fora das otimizações de bateria do Android"
                            : "O aplicativo declara a capacidade de solicitar uma exceção de otimização de bateria, mas ela não foi identificada como ativa",
                    p.packageName, exempt ? 3 : 0,
                    exempt
                            ? "Confirme se o aplicativo realmente precisa permanecer fora das otimizações"
                            : null);
            if (exempt) {
                batteryFinding = batteryFinding.withTags(
                        ScanFinding.EvidenceTag.ACTIVE_ACCESS,
                        ScanFinding.EvidenceTag.PERSISTENCE);
            }
            out.add(batteryFinding);
        }

        if (isPermissionGranted("android.permission.REQUEST_INSTALL_PACKAGES", p.packageName)) {
            out.add(new ScanFinding(
                    ScanFinding.Level.MEDIUM, "Pode solicitar instalação de APKs",
                    "O aplicativo tem acesso operacional à capacidade de solicitar instalações",
                    p.packageName, 4,
                    "Verifique se a instalação de APKs faz parte da função esperada")
                    .withTags(
                            ScanFinding.EvidenceTag.ACTIVE_ACCESS,
                            ScanFinding.EvidenceTag.INSTALL_TRUST));
        }

        if (!system && ps.contains("android.permission.RECEIVE_BOOT_COMPLETED")) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW,
                    "Inicialização automática declarada",
                    label + " declara receber o evento de inicialização do Android",
                    p.packageName, 1,
                    "Confirme se iniciar após o boot é esperado para este aplicativo")
                    .withTags(ScanFinding.EvidenceTag.PERSISTENCE));
        }

        inspectDeclaredCapabilities(p, ps, system, out);

        if (hasAccessibilityService(p)) {
            ScanFinding.Level lvl = system ? ScanFinding.Level.INFO : ScanFinding.Level.MEDIUM;
            int points = system ? 0 : 5;
            out.add(new ScanFinding(
                    lvl, "Serviço de acessibilidade declarado",
                    system ? label + " é um app de sistema"
                           : label + " possui um serviço que pode interagir com a interface",
                    p.packageName, points, "Verifique se é um serviço que você reconhece"));
        }

        if (remoteMarker) {
            boolean corroborated = shouldElevateRemoteMarker(sensitive, overlayGranted);
            out.add(new ScanFinding(
                    corroborated ? ScanFinding.Level.MEDIUM : ScanFinding.Level.LOW,
                    "Indicador heurístico de acesso remoto",
                    "Nome do app/pacote contém um marcador associado a suporte ou acesso remoto; isso sozinho não prova malware",
                    p.packageName, corroborated ? 4 : 1,
                    "Confirme se você instalou e reconhece este aplicativo")
                    .withTags(ScanFinding.EvidenceTag.REMOTE_CONTROL));
        }

        if (!system) {
            String installer = getInstaller(p.packageName);
            if (installer == null || installer.trim().isEmpty()) {
                out.add(new ScanFinding(
                        ScanFinding.Level.INFO, "Origem de instalação não identificada",
                        "O Android não informou um instalador conhecido para este aplicativo",
                        p.packageName, 0,
                        "Confirme a origem do APK se você não reconhecer o app"));
            } else {
                out.add(new ScanFinding(
                        ScanFinding.Level.INFO, "Origem de instalação",
                        "Instalador informado pelo Android: " + installer,
                        p.packageName, 0, null));
            }
        }

        if (debuggable && !system) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO, "Aplicativo debuggable",
                    label + " está marcado como debuggable",
                    p.packageName, 0,
                    "Normal em apps de teste; confirme a origem se não for esperado"));
        }

        if (!system && ai.targetSdkVersion > 0 && ai.targetSdkVersion < 23) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW, "Aplicativo com target SDK muito antigo",
                    label + " declara target SDK " + ai.targetSdkVersion
                            + "; versões muito antigas ficam fora de várias proteções modernas do Android",
                    p.packageName, 2,
                    "Confirme a origem e mantenha o aplicativo atualizado quando houver versão compatível"));
        } else if (!system && ai.targetSdkVersion > 0 && ai.targetSdkVersion < 26) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW, "Aplicativo com target SDK antigo",
                    label + " declara target SDK " + ai.targetSdkVersion,
                    p.packageName, 1,
                    "Confirme a origem e prefira uma versão atualizada quando disponível"));
        }

        if (!system && (ai.flags & ApplicationInfo.FLAG_TEST_ONLY) != 0) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO, "Aplicativo marcado como testOnly",
                    label + " está marcado como testOnly",
                    p.packageName, 0,
                    "Normal em builds de desenvolvimento; confirme a origem se você não esperava um app de teste"));
        }

        if (!system && (ai.flags & ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO, "Aplicativo permite tráfego sem criptografia",
                    label + " pode usar tráfego cleartext, como HTTP; isso não prova comportamento malicioso",
                    p.packageName, 0,
                    "Revise essa configuração se o aplicativo manipular dados sensíveis"));
        }

        if (!system) {
            inspectExportedComponents(p, out);
        }

        if (hasVpnService(p) && !system) {
            out.add(new ScanFinding(
                    ScanFinding.Level.MEDIUM, "Serviço VPN declarado",
                    "O aplicativo declara um serviço BIND_VPN_SERVICE; VPN legítima é comum, mas vale revisar apps desconhecidos",
                    p.packageName, 3,
                    "Confirme se a VPN é esperada e reconhecida"));
        }

        String cert = signingSha256(p);
        if (cert != null) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO, "Assinatura SHA-256",
                    cert, p.packageName, 0, null));
        }

        if (!system && ai.sourceDir != null && !ai.sourceDir.isEmpty()) {
            out.addAll(StaticApkAnalyzer.analyzeInstalled(
                    ai.sourceDir, ai.splitSourceDirs, p.packageName));
        }
    }

    /**
     * A name associated with remote support is only elevated by capabilities
     * confirmed as operational. Merely declaring an accessibility service is
     * intentionally excluded here; active accessibility is collected later and
     * correlated by {@link ThreatCorrelationEngine}.
     */
    static boolean shouldElevateRemoteMarker(
            int operationalSensitiveCount, boolean overlayGranted) {
        return operationalSensitiveCount >= 2 || overlayGranted;
    }

    static String defaultInputMethodPackage(String setting) {
        if (setting == null) return null;
        String value = setting.trim();
        int separator = value.indexOf('/');
        if (separator <= 0 || separator >= value.length() - 1) return null;
        String packageName = value.substring(0, separator).trim();
        String serviceName = value.substring(separator + 1).trim();
        return packageName.isEmpty() || serviceName.isEmpty() ? null : packageName;
    }

    private void checkDefaultInputMethod(List<ScanFinding> out) {
        String setting;
        try {
            setting = Settings.Secure.getString(
                    c.getContentResolver(), Settings.Secure.DEFAULT_INPUT_METHOD);
        } catch (Exception e) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW,
                    "Teclado padrão",
                    "Não foi possível consultar o método de entrada padrão",
                    null, 1,
                    "Revise manualmente o teclado configurado em Configurações > Sistema > Teclado"));
            return;
        }

        String pkg = defaultInputMethodPackage(setting);
        if (pkg == null) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "Teclado padrão",
                    "Nenhum método de entrada padrão foi identificado",
                    null, 0, null));
            return;
        }

        boolean system = isSystemPackage(pkg);
        out.add(new ScanFinding(
                system ? ScanFinding.Level.INFO : ScanFinding.Level.LOW,
                system ? "Teclado padrão do sistema" : "Teclado de terceiros ativo",
                "Método de entrada padrão: " + setting,
                pkg,
                system ? 0 : 2,
                system
                        ? null
                        : "Confirme se você reconhece e confia no teclado; métodos de entrada podem processar o texto digitado"));
    }

    private void checkDefaultCommunicationApps(List<ScanFinding> out) {
        String defaultSms = null;
        try {
            defaultSms = android.provider.Telephony.Sms.getDefaultSmsPackage(c);
        } catch (Exception ignored) {}

        addDefaultHandlerFinding(out,
                defaultSms,
                "Aplicativo padrão de SMS",
                "O aplicativo padrão de SMS pode processar mensagens recebidas e enviadas",
                "Confirme se você reconhece o aplicativo definido como padrão para SMS");

        String defaultDialer = null;
        try {
            android.telecom.TelecomManager telecom =
                    (android.telecom.TelecomManager) c.getSystemService(Context.TELECOM_SERVICE);
            if (telecom != null) defaultDialer = telecom.getDefaultDialerPackage();
        } catch (Exception ignored) {}

        addDefaultHandlerFinding(out,
                defaultDialer,
                "Aplicativo padrão de chamadas",
                "O aplicativo padrão de chamadas pode controlar a experiência de telefonia do dispositivo",
                "Confirme se você reconhece o aplicativo definido como padrão para chamadas");
    }

    private void addDefaultHandlerFinding(
            List<ScanFinding> out,
            String packageName,
            String title,
            String detail,
            String action) {
        if (packageName == null || packageName.trim().isEmpty()) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO, title,
                    "O Android não informou um aplicativo padrão",
                    null, 0, null));
            return;
        }

        boolean system = isSystemPackage(packageName);
        out.add(new ScanFinding(
                ScanFinding.Level.INFO,
                system ? title + " do sistema" : title + " de terceiros",
                detail,
                packageName,
                0,
                system ? null : action));
    }

    private void checkSystemIntegrity(List<ScanFinding> out) {
        boolean rootBinary = SystemIntegrityChecker.hasRootBinary();
        boolean testKeys = SystemIntegrityChecker.hasTestKeys();
        boolean debuggableBuild = SystemIntegrityChecker.hasDebuggableBuild();
        boolean rootMarker = SystemIntegrityChecker.hasRootManagementMarker();

        if (rootBinary) {
            out.add(new ScanFinding(
                    ScanFinding.Level.HIGH, "Binário de root detectado",
                    "Foi encontrado um executável su em um caminho conhecido; isso indica alteração do ambiente do sistema, mas não identifica sozinho qual aplicativo fez a alteração",
                    null, 8,
                    "Revise o estado do dispositivo e aplicativos que exigem root"));
        } else if (testKeys) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW, "Build assinado com test-keys",
                    "O sistema reporta uma assinatura de build normalmente associada a builds de teste/desenvolvimento",
                    null, 1,
                    "Confirme a origem da ROM se o aparelho deveria usar uma build oficial"));
        }

        if (debuggableBuild) {
            out.add(new ScanFinding(
                    ScanFinding.Level.MEDIUM, "Build do sistema debuggable",
                    "O tipo de build é eng/userdebug; isso é comum em ambientes de desenvolvimento",
                    null, 3,
                    "Revise apenas se esse estado não for esperado no seu dispositivo"));
        }

        if (rootMarker) {
            out.add(new ScanFinding(
                    ScanFinding.Level.MEDIUM, "Indicador de gerenciamento de root",
                    "Foram encontrados marcadores de ferramentas/estado de gerenciamento de root em locais observáveis",
                    null, 4,
                    "Revise ferramentas de root instaladas e o estado de integridade do sistema"));
        }

        if (!rootBinary && !testKeys && !debuggableBuild && !rootMarker) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO, "Integridade básica do sistema",
                    "Nenhum dos indicadores locais de root/build de teste foi detectado",
                    null, 0, null));
        }
    }

    private void checkNetworkState(List<ScanFinding> out) {
        ConnectivityManager cm =
                (ConnectivityManager) c.getSystemService(Context.CONNECTIVITY_SERVICE);

        Network active = null;
        NetworkCapabilities caps = null;
        String proxy = SystemIntegrityChecker.getProxyHost();

        try {
            if (cm != null) {
                active = cm.getActiveNetwork();
                caps = active == null ? null : cm.getNetworkCapabilities(active);
                if (proxy == null || proxy.isEmpty()) {
                    proxy = getNetworkProxyHost(cm, active);
                }
            }
        } catch (SecurityException ignored) {
            // Fall back to process properties and report the restricted VPN state below.
        }

        if (proxy != null && !proxy.isEmpty()) {
            out.add(new ScanFinding(
                    ScanFinding.Level.MEDIUM, "Proxy de rede configurado",
                    "Host de proxy observado: " + proxy,
                    null, 3,
                    "Confirme se o proxy foi configurado conscientemente"));
        } else {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO, "Proxy de rede",
                    "Nenhum proxy HTTP/HTTPS foi observado",
                    null, 0, null));
        }

        if (cm == null) return;

        try {
            boolean vpn = caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
            out.add(new ScanFinding(
                    vpn ? ScanFinding.Level.MEDIUM : ScanFinding.Level.INFO,
                    "VPN ativa",
                    vpn ? "A rede ativa usa transporte VPN"
                        : "Nenhuma VPN ativa foi identificada pela rede ativa",
                    null, vpn ? 3 : 0,
                    vpn ? "Confirme se a VPN ativa é esperada e reconhecida" : null));
        } catch (SecurityException e) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW, "Estado de VPN",
                    "O sistema restringiu a consulta do estado de rede",
                    null, 1, null));
        }

        checkPrivateDns(cm, active, out);
    }

    private void checkPrivateDns(ConnectivityManager cm, Network active,
                                 List<ScanFinding> out) {
        if (Build.VERSION.SDK_INT < 28) return;
        if (active == null) {
            out.add(new ScanFinding(ScanFinding.Level.INFO, "DNS privado da rede ativa",
                    "Indisponível: nenhuma rede ativa foi identificada", null, 0, null));
            return;
        }
        try {
            LinkProperties properties = cm.getLinkProperties(active);
            if (properties == null) {
                out.add(new ScanFinding(ScanFinding.Level.INFO, "DNS privado da rede ativa",
                        "Indisponível: o Android não forneceu os dados da rede", null, 0, null));
                return;
            }
            out.add(privateDnsFinding(properties.isPrivateDnsActive(),
                    properties.getPrivateDnsServerName()));
        } catch (SecurityException e) {
            out.add(new ScanFinding(ScanFinding.Level.INFO, "DNS privado da rede ativa",
                    "Indisponível: o Android restringiu a consulta da rede", null, 0, null));
        }
    }

    static ScanFinding privateDnsFinding(boolean active, String serverName) {
        String server = serverName == null ? "" : serverName
                .replaceAll("[\\p{Cntrl}]", " ").trim();
        if (server.length() > 253) server = server.substring(0, 253) + "…";
        String detail = !active
                ? "DNS privado não está ativo nesta rede; isso não indica malware"
                : server.isEmpty()
                ? "DNS privado ativo em modo oportunista nesta rede"
                : "DNS privado ativo com provedor: " + server;
        return new ScanFinding(ScanFinding.Level.INFO, "DNS privado da rede ativa",
                detail + ". VPNs e aplicativos podem usar resolução própria.", null, 0,
                "Revise as configurações de DNS privado do Android se o provedor for desconhecido");
    }

    private String getNetworkProxyHost(ConnectivityManager cm, Network active) {
        if (active == null) return "";
        try {
            LinkProperties lp = cm.getLinkProperties(active);
            if (lp == null) return "";
            ProxyInfo proxy = lp.getHttpProxy();
            return proxy == null || proxy.getHost() == null ? "" : proxy.getHost();
        } catch (SecurityException e) {
            return "";
        }
    }

    private void inspectExportedComponents(PackageInfo p, List<ScanFinding> out) {
        int exportedActivities = 0;
        int exportedServices = 0;
        int exportedReceivers = 0;
        int exportedProviders = 0;
        int unprotectedActivities = 0;
        int unprotectedServices = 0;
        int unprotectedReceivers = 0;
        int unprotectedProviders = 0;

        if (p.activities != null) {
            for (android.content.pm.ActivityInfo activity : p.activities) {
                if (!activity.exported) continue;
                exportedActivities++;
                if (TextUtils.isEmpty(activity.permission)) unprotectedActivities++;
            }
        }

        if (p.services != null) {
            for (ServiceInfo s : p.services) {
                if (!s.exported) continue;
                exportedServices++;
                if (TextUtils.isEmpty(s.permission)) unprotectedServices++;
            }
        }

        if (p.receivers != null) {
            for (android.content.pm.ActivityInfo r : p.receivers) {
                if (!r.exported) continue;
                exportedReceivers++;
                if (TextUtils.isEmpty(r.permission)) unprotectedReceivers++;
            }
        }

        if (p.providers != null) {
            for (android.content.pm.ProviderInfo provider : p.providers) {
                if (!provider.exported) continue;
                exportedProviders++;
                if (isUnprotectedExportedProvider(provider)) {
                    unprotectedProviders++;
                }
            }
        }

        int unprotected = unprotectedActivities + unprotectedServices
                + unprotectedReceivers + unprotectedProviders;
        int total = exportedActivities + exportedServices + exportedReceivers + exportedProviders;
        if (total == 0) return;

        if (unprotectedProviders > 0) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW,
                    "Content provider exportado sem proteção",
                    "Há " + unprotectedProviders
                            + " provider(s) exportado(s) sem readPermission/writePermission explícitas. "
                            + "Providers podem expor dados a outros aplicativos e merecem revisão.",
                    p.packageName, 2,
                    "Revise o provider e use permissões adequadas ou exported=false quando ele não precisar ser público"));
        } else if (unprotected > 0) {
            // Exported activities/receivers/services without a permission can be
            // legitimate public entry points. Report them without scoring to
            // avoid treating common launcher/API components as malware evidence.
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "Componentes exportados revisados",
                    "Activities: " + exportedActivities + " (" + unprotectedActivities + " sem permissão explícita); "
                            + "serviços: " + exportedServices + " (" + unprotectedServices + " sem permissão explícita); "
                            + "receivers: " + exportedReceivers + " (" + unprotectedReceivers + " sem permissão explícita); "
                            + "providers: " + exportedProviders + ". Componentes públicos podem ser legítimos.",
                    p.packageName, 0, null));
        } else {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "Componentes exportados protegidos",
                    "Activities: " + exportedActivities + "; serviços: " + exportedServices
                            + "; receivers: " + exportedReceivers + "; providers: " + exportedProviders,
                    p.packageName, 0, null));
        }
    }

    private boolean hasVpnService(PackageInfo p) {
        if (p.services == null) return false;
        for (ServiceInfo s : p.services) {
            if ("android.permission.BIND_VPN_SERVICE".equals(s.permission)) return true;
        }
        return false;
    }

    /**
     * Reports capabilities that require an explicit Android component declaration.
     * A declaration is not equivalent to active use, so these findings remain
     * informational unless another observed signal corroborates them.
     */
    private void inspectDeclaredCapabilities(
            PackageInfo p,
            Set<String> requestedPermissions,
            boolean system,
            List<ScanFinding> out) {
        if (system) return;

        boolean notificationListener = false;
        boolean inputMethod = false;
        boolean autofill = false;
        boolean mediaProjection = requestedPermissions.contains(
                "android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION");

        if (p.services != null) {
            for (ServiceInfo service : p.services) {
                if (service == null) continue;
                String permission = service.permission;
                if ("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE".equals(permission)) {
                    notificationListener = true;
                } else if ("android.permission.BIND_INPUT_METHOD".equals(permission)) {
                    inputMethod = true;
                } else if ("android.permission.BIND_AUTOFILL_SERVICE".equals(permission)) {
                    autofill = true;
                }

                if (Build.VERSION.SDK_INT >= 29
                        && isMediaProjectionForegroundService(
                                service.getForegroundServiceType())) {
                    mediaProjection = true;
                }
            }
        }

        boolean deviceAdmin = false;
        if (p.receivers != null) {
            for (android.content.pm.ActivityInfo receiver : p.receivers) {
                if (receiver != null && isDeviceAdminReceiverPermission(receiver.permission)) {
                    deviceAdmin = true;
                    break;
                }
            }
        }

        if (mediaProjection) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "Capacidade de captura de tela declarada",
                    "O aplicativo declara serviço/permissão de MediaProjection. O Android exige consentimento do usuário para cada sessão, mas uma sessão autorizada pode capturar conteúdo exibido na tela.",
                    p.packageName, 0,
                    "Autorize compartilhamento ou gravação de tela somente quando você iniciar e reconhecer a função"));
        }
        if (notificationListener) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "Listener de notificações declarado",
                    "O aplicativo declara um serviço que pode receber acesso às notificações se você o habilitar; esta declaração não significa que o acesso esteja ativo.",
                    p.packageName, 0,
                    "Revise o acesso apenas se o aplicativo aparecer como ativo nas Configurações"));
        }
        if (inputMethod) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "Método de entrada declarado",
                    "O aplicativo pode oferecer um teclado. A declaração não significa que ele seja o teclado ativo.",
                    p.packageName, 0,
                    "Use apenas teclados reconhecidos e confirme qual está definido como padrão"));
        }
        if (autofill) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "Serviço de preenchimento automático declarado",
                    "O aplicativo pode oferecer preenchimento automático de formulários e credenciais, caso seja escolhido pelo usuário.",
                    p.packageName, 0,
                    "Confirme nas Configurações qual serviço de preenchimento automático está ativo"));
        }
        if (deviceAdmin) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "Administrador do dispositivo declarado",
                    "O aplicativo declara um receptor de administrador do dispositivo. Isso não significa que o privilégio esteja ativo.",
                    p.packageName, 0,
                    "Revise apenas se o aplicativo também aparecer como administrador ativo"));
        }
    }

    static boolean isMediaProjectionForegroundService(int foregroundServiceType) {
        return (foregroundServiceType
                & ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION) != 0;
    }

    static boolean isDeviceAdminReceiverPermission(String permission) {
        return "android.permission.BIND_DEVICE_ADMIN".equals(permission);
    }

    private boolean isIgnoringBatteryOptimizations(String packageName) {
        try {
            PowerManager powerManager =
                    (PowerManager) c.getSystemService(Context.POWER_SERVICE);
            return powerManager != null && powerManager.isIgnoringBatteryOptimizations(packageName);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean hasSpecialAccess(String permission, String packageName) {
        try {
            ApplicationInfo ai = appInfoCache.get(packageName);
            if (ai == null) {
                ai = pm.getApplicationInfo(packageName, 0);
                appInfoCache.put(packageName, ai);
            }
            if (appOps == null) return false;

            String op = AppOpsManager.permissionToOp(permission);
            if (op == null
                    && "android.permission.MANAGE_EXTERNAL_STORAGE".equals(permission)
                    && Build.VERSION.SDK_INT >= 30) {
                op = "android:manage_external_storage";
            }
            if (op == null) return false;

            return appOps.checkOpNoThrow(op, ai.uid, packageName)
                    == AppOpsManager.MODE_ALLOWED;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isPermissionGranted(String permission, String packageName) {
        try {
            // A granted AppOp alone does not prove that a dangerous/runtime
            // permission was granted to this package. Usage access and overlay
            // are special app-op grants and must be handled separately.
            boolean appOpOnly = "android.permission.SYSTEM_ALERT_WINDOW".equals(permission)
                    || "android.permission.PACKAGE_USAGE_STATS".equals(permission);
            if (!appOpOnly && pm.checkPermission(permission, packageName)
                    != PackageManager.PERMISSION_GRANTED) return false;
            String op = AppOpsManager.permissionToOp(permission);
            if (op != null && appOps != null) {
                ApplicationInfo ai = appInfoCache.get(packageName);
                if (ai == null) {
                    ai = pm.getApplicationInfo(packageName, 0);
                    appInfoCache.put(packageName, ai);
                }
                if (appOps != null) {
                    int mode = appOps.checkOpNoThrow(op, ai.uid, packageName);
                    if (mode == AppOpsManager.MODE_ALLOWED) return true;
                    if (Build.VERSION.SDK_INT >= 29
                            && mode == AppOpsManager.MODE_FOREGROUND) return true;
                    if (mode != AppOpsManager.MODE_DEFAULT) return false;
                }
            }
            return pm.checkPermission(permission, packageName)
                    == PackageManager.PERMISSION_GRANTED;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean hasAccessibilityService(PackageInfo p) {
        if (p.services == null) return false;
        for (ServiceInfo s : p.services) {
            if ("android.permission.BIND_ACCESSIBILITY_SERVICE".equals(s.permission)) return true;
        }
        return false;
    }

    private boolean containsRemoteControlMarker(String s) {
        for (String marker : REMOTE_MARKERS) {
            if (s.contains(marker)) return true;
        }
        return false;
    }

    private boolean isSystemApp(ApplicationInfo ai) {
        return (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                || (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;
    }

    private String safeLabel(ApplicationInfo ai) {
        try {
            return String.valueOf(pm.getApplicationLabel(ai));
        } catch (Exception e) {
            return ai.packageName;
        }
    }

    private String getInstaller(String packageName) {
        try {
            if (Build.VERSION.SDK_INT >= 30) {
                return pm.getInstallSourceInfo(packageName).getInstallingPackageName();
            }
            return pm.getInstallerPackageName(packageName);
        } catch (Exception e) {
            return null;
        }
    }

    private void addBaseline(List<ScanFinding> out) {
        int dev = 0, adb = 0;
        try {
            dev = Settings.Global.getInt(
                    c.getContentResolver(),
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0);
        } catch (Exception ignored) {}
        try {
            adb = Settings.Global.getInt(
                    c.getContentResolver(), Settings.Global.ADB_ENABLED, 0);
        } catch (Exception ignored) {}

        out.add(new ScanFinding(
                ScanFinding.Level.INFO,
                "Opções do desenvolvedor",
                dev == 1 ? "Ativadas" : "Desativadas",
                null, 0,
                null));

        out.add(new ScanFinding(
                adb == 1 ? ScanFinding.Level.MEDIUM : ScanFinding.Level.INFO,
                "Depuração USB (ADB)",
                adb == 1 ? "Ativada" : "Desativada",
                null, adb == 1 ? 4 : 0,
                adb == 1 ? "Desative quando não estiver usando ADB" : null));

        checkDevicePosture(out);
        checkDefaultInputMethod(out);
        checkDefaultCommunicationApps(out);
    }

    private void checkDevicePosture(List<ScanFinding> out) {
        try {
            KeyguardManager keyguard =
                    (KeyguardManager) c.getSystemService(Context.KEYGUARD_SERVICE);
            if (keyguard != null) {
                boolean secure = keyguard.isDeviceSecure();
                out.add(new ScanFinding(
                        ScanFinding.Level.INFO,
                        "Bloqueio de tela seguro",
                        secure ? "Um método de bloqueio seguro está configurado"
                               : "Nenhum método de bloqueio seguro foi identificado",
                        null, 0,
                        secure ? null
                               : "Configure PIN, senha ou padrão para reforçar a proteção física do dispositivo"));
            }
        } catch (SecurityException ignored) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO,
                    "Bloqueio de tela seguro",
                    "Não foi possível consultar o estado do bloqueio de tela",
                    null, 0, null));
        }

        String patch = Build.VERSION.SECURITY_PATCH;
        out.add(new ScanFinding(
                ScanFinding.Level.INFO,
                "Nível do patch de segurança",
                patch == null || patch.trim().isEmpty()
                        ? "O sistema não informou a data do patch de segurança"
                        : patch,
                null, 0, null));
        addSecurityPatchAgeFinding(out, patch);
        out.addAll(SecurityStateScanner.scan(c));
    }

    static int securityPatchAgeDays(String patch, LocalDate today) {
        if (patch == null || patch.trim().isEmpty() || today == null) return -1;
        try {
            LocalDate patchDate = LocalDate.parse(patch.trim());
            long days = java.time.temporal.ChronoUnit.DAYS.between(patchDate, today);
            if (days < 0 || days > Integer.MAX_VALUE) return -1;
            return (int) days;
        } catch (DateTimeParseException e) {
            return -1;
        }
    }

    private void addSecurityPatchAgeFinding(List<ScanFinding> out, String patch) {
        int age = securityPatchAgeDays(patch, LocalDate.now());
        if (age < 0) return;
        if (age >= 365) {
            out.add(new ScanFinding(
                    ScanFinding.Level.HIGH,
                    "Patch de segurança muito antigo",
                    "O patch informado pelo Android tem aproximadamente " + age
                            + " dia(s). A ausência de atualizações recentes aumenta a exposição a vulnerabilidades conhecidas.",
                    null, 6,
                    "Procure atualizações do sistema e do fabricante"));
        } else if (age >= 180) {
            out.add(new ScanFinding(
                    ScanFinding.Level.MEDIUM,
                    "Patch de segurança desatualizado",
                    "O patch informado pelo Android tem aproximadamente " + age
                            + " dia(s). Verifique se há atualização disponível para o dispositivo.",
                    null, 4,
                    "Procure atualizações do sistema e do fabricante"));
        }
    }

    static boolean isUnprotectedExportedProvider(android.content.pm.ProviderInfo provider) {
        if (provider == null) return false;
        return isUnprotectedExportedProvider(
                provider.exported,
                provider.readPermission,
                provider.writePermission);
    }

    static boolean isUnprotectedExportedProvider(
            boolean exported, String readPermission, String writePermission) {
        return exported
                && (readPermission == null || readPermission.trim().isEmpty())
                && (writePermission == null || writePermission.trim().isEmpty());
    }

    private void checkAccessibility(List<ScanFinding> out) {
        AccessibilityManager am =
                (AccessibilityManager) c.getSystemService(Context.ACCESSIBILITY_SERVICE);
        if (am == null) return;

        List<AccessibilityServiceInfo> enabled;
        try {
            enabled = am.getEnabledAccessibilityServiceList(
                    AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
        } catch (Exception e) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW, "Serviços de acessibilidade ativos",
                    "Não foi possível consultar os serviços ativos; o sistema restringiu ou recusou a consulta",
                    null, 1,
                    "Revise manualmente em Configurações > Acessibilidade"));
            return;
        }

        if (enabled == null || enabled.isEmpty()) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO, "Serviços de acessibilidade ativos",
                    "Nenhum serviço retornado como ativo",
                    null, 0, null));
            return;
        }

        for (AccessibilityServiceInfo info : enabled) {
            ComponentName cn = null;
            try {
                ServiceInfo si = info.getResolveInfo().serviceInfo;
                cn = new ComponentName(si.packageName, si.name);
            } catch (Exception ignored) {}

            String pkg = cn == null ? null : cn.getPackageName();
            boolean system = pkg != null && isSystemPackage(pkg);

            out.add(new ScanFinding(
                    system ? ScanFinding.Level.LOW : ScanFinding.Level.HIGH,
                    "Serviço de acessibilidade ativo",
                    cn == null ? "Serviço ativo detectado" : cn.flattenToShortString(),
                    pkg, system ? 1 : 8,
                    system
                            ? "Revise apenas se não reconhecer o componente"
                            : "Abra Acessibilidade e confirme se você o ativou conscientemente")
                    .withTags(ScanFinding.EvidenceTag.ACTIVE_ACCESS));
        }
    }

    private boolean isSystemPackage(String pkg) {
        try {
            return isSystemApp(pm.getApplicationInfo(pkg, 0));
        } catch (Exception e) {
            return false;
        }
    }

    private void checkNotificationListeners(List<ScanFinding> out) {
        try {
            String v = Settings.Secure.getString(
                    c.getContentResolver(), "enabled_notification_listeners");
            if (TextUtils.isEmpty(v)) {
                out.add(new ScanFinding(
                        ScanFinding.Level.INFO, "Acesso a notificações",
                        "Nenhum listener ativo", null, 0, null));
                return;
            }

            String[] entries = v.split(":");
            int recognized = 0;
            for (String entry : entries) {
                if (TextUtils.isEmpty(entry)) continue;

                ComponentName component = ComponentName.unflattenFromString(entry);
                String pkg = component == null ? null : component.getPackageName();
                if (pkg == null) continue;

                recognized++;
                boolean system = isSystemPackage(pkg);
                out.add(new ScanFinding(
                        system ? ScanFinding.Level.LOW : ScanFinding.Level.MEDIUM,
                        "Acesso a notificações ativo",
                        component.flattenToShortString(),
                        pkg,
                        system ? 1 : 3,
                        "Confirme se este aplicativo precisa ler notificações do dispositivo")
                        .withTags(
                                ScanFinding.EvidenceTag.ACTIVE_ACCESS,
                                ScanFinding.EvidenceTag.SENSITIVE_DATA));
            }

            if (recognized == 0) {
                out.add(new ScanFinding(
                        ScanFinding.Level.LOW,
                        "Acesso a notificações",
                        "Há listeners registrados, mas nenhum componente pôde ser associado a um pacote",
                        null, 1,
                        "Revise em Configurações > Acesso a notificações"));
            } else {
                out.add(new ScanFinding(
                        ScanFinding.Level.INFO,
                        "Listeners de notificações analisados",
                        recognized + " componente(s) associado(s) a pacotes",
                        null, 0, null));
            }
        } catch (Exception e) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW, "Acesso a notificações",
                    "Não foi possível consultar", null, 1, null));
        }
    }

    private void checkDeviceAdmins(List<ScanFinding> out) {
        DevicePolicyManager dpm =
                (DevicePolicyManager) c.getSystemService(Context.DEVICE_POLICY_SERVICE);
        if (dpm == null) return;

        try {
            List<ComponentName> admins = dpm.getActiveAdmins();
            if (admins == null || admins.isEmpty()) {
                out.add(new ScanFinding(
                        ScanFinding.Level.INFO, "Administradores do dispositivo",
                        "Nenhum administrador ativo", null, 0, null));
            } else {
                for (ComponentName n : admins) {
                    String pkg = n.getPackageName();
                    boolean system = isSystemPackage(pkg);
                    boolean deviceOwner = false;
                    boolean profileOwner = false;
                    try {
                        deviceOwner = dpm.isDeviceOwnerApp(pkg);
                        profileOwner = dpm.isProfileOwnerApp(pkg);
                    } catch (SecurityException ignored) {
                        // Keep the regular active-admin finding when ownership state is restricted.
                    }

                    out.add(new ScanFinding(
                            system ? ScanFinding.Level.LOW : ScanFinding.Level.HIGH,
                            "Administrador do dispositivo ativo",
                            n.flattenToShortString(), pkg, system ? 1 : 8,
                            "Revise em Configurações > Segurança/Administradores do dispositivo")
                            .withTags(ScanFinding.EvidenceTag.ACTIVE_ACCESS));

                    if (deviceOwner || profileOwner) {
                        out.add(new ScanFinding(
                                system ? ScanFinding.Level.LOW : ScanFinding.Level.MEDIUM,
                                deviceOwner && profileOwner
                                        ? "App é administrador do dispositivo e do perfil"
                                        : deviceOwner
                                                ? "App é proprietário do dispositivo"
                                                : "App é proprietário do perfil",
                                deviceOwner && profileOwner
                                        ? "O pacote está registrado como Device Owner e Profile Owner"
                                        : deviceOwner
                                                ? "O pacote está registrado como Device Owner"
                                                : "O pacote está registrado como Profile Owner",
                                pkg, system ? 0 : 4,
                                "Confirme se este gerenciamento corporativo ou de perfil foi autorizado por você")
                                .withTags(ScanFinding.EvidenceTag.ACTIVE_ACCESS));
                    }
                }
            }
        } catch (SecurityException e) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW, "Administradores do dispositivo",
                    "A consulta foi restringida pelo sistema",
                    null, 1, null));
        }
    }

    private String signingSha256(PackageInfo p) {
        try {
            android.content.pm.Signature[] sigs;
            if (Build.VERSION.SDK_INT >= 28) {
                if (p.signingInfo == null) return null;
                sigs = p.signingInfo.hasMultipleSigners()
                        ? p.signingInfo.getApkContentsSigners()
                        : p.signingInfo.getSigningCertificateHistory();
            } else {
                sigs = p.signatures;
            }
            if (sigs == null || sigs.length == 0) return null;

            List<String> hashes = new ArrayList<>(sigs.length);
            if (Build.VERSION.SDK_INT >= 28
                    && !p.signingInfo.hasMultipleSigners()) {
                // Signing certificate history is ordered from original to current.
                hashes.add(sha256(sigs[sigs.length - 1].toByteArray()));
            } else {
                // Multiple signers have set semantics; sort for deterministic reporting.
                for (android.content.pm.Signature sig : sigs) {
                    if (sig == null) continue;
                    String hash = sha256(sig.toByteArray());
                    if (hash != null) hashes.add(hash);
                }
                Collections.sort(hashes);
            }
            if (hashes.isEmpty()) return null;
            return String.join(", ", hashes);
        } catch (Exception e) {
            return null;
        }
    }

    private String sha256(byte[] bytes) {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-256");
            byte[] digest = d.digest(bytes);
            StringBuilder sb = new StringBuilder();
            for (byte x : digest) {
                sb.append(String.format(Locale.ROOT, "%02X", x));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }
}
