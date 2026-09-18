package com.darkshield.security;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.AppOpsManager;
import android.app.admin.DevicePolicyManager;
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
import android.provider.Settings;
import android.text.TextUtils;
import android.view.accessibility.AccessibilityManager;
import java.security.MessageDigest;
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
        "android.permission.PACKAGE_USAGE_STATS","android.permission.READ_PHONE_STATE"
    };
    private static final Set<String> REMOTE_MARKERS = new HashSet<>(Arrays.asList(
        "anydesk","teamviewer","airdroid","rustdesk","splashtop","vysor","scrcpy",
        "remotecontrol","remote support","remote desktop","remote access"
    ));
    private final Context c;
    private final PackageManager pm;

    public SecurityScanner(Context c) {
        this.c = c.getApplicationContext();
        this.pm = c.getPackageManager();
    }

    public List<ScanFinding> scan() {
        List<ScanFinding> out = new ArrayList<>();
        addBaseline(out);
        List<PackageInfo> apps = getApps();
        out.add(new ScanFinding(
                ScanFinding.Level.INFO, "Aplicativos analisados",
                apps.size() + " pacote(s) visíveis para o scanner", null, 0, null));
        for (PackageInfo p : apps) inspectApp(p, out);
        checkAccessibility(out);
        checkNotificationListeners(out);
        checkDeviceAdmins(out);
        out.addAll(ThreatCorrelationEngine.correlate(out));
        checkSystemIntegrity(out);
        checkNetworkState(out);
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
            return Collections.emptyList();
        }
    }

    private void inspectApp(PackageInfo p, List<ScanFinding> out) {
        ApplicationInfo ai = p.applicationInfo;
        if (ai == null || c.getPackageName().equals(p.packageName)) return;

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

        if (isPermissionGranted("android.permission.SYSTEM_ALERT_WINDOW", p.packageName)) {
            out.add(new ScanFinding(
                    sideLoad ? ScanFinding.Level.MEDIUM : ScanFinding.Level.LOW,
                    "Permissão de sobreposição concedida",
                    label, p.packageName, sideLoad ? 4 : 2,
                    "Revisar em Configurações > Apps > Acesso especial"));
        } else if (ps.contains("android.permission.SYSTEM_ALERT_WINDOW")) {
            out.add(new ScanFinding(
                    ScanFinding.Level.INFO, "Sobreposição declarada",
                    "A permissão foi declarada, mas não consta como concedida",
                    p.packageName, 0, null));
        }

        int mediaCount = 0;
        if (isPermissionGranted("android.permission.RECORD_AUDIO", p.packageName)) mediaCount++;
        if (isPermissionGranted("android.permission.CAMERA", p.packageName)) mediaCount++;
        if (mediaCount > 0) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW, "Acesso a microfone/câmera",
                    label + " solicita " + mediaCount + " recurso(s) de áudio/vídeo",
                    p.packageName, 1, "Confirme se essa função é necessária"));
        }

        if (isPermissionGranted("android.permission.READ_SMS", p.packageName)
                || isPermissionGranted("android.permission.RECEIVE_SMS", p.packageName)
                || isPermissionGranted("android.permission.SEND_SMS", p.packageName)) {
            out.add(new ScanFinding(
                    ScanFinding.Level.MEDIUM, "Acesso a SMS",
                    "O aplicativo possui acesso operacional a mensagens SMS",
                    p.packageName, 4, "Revisar a permissão e a finalidade do aplicativo"));
        }

        if (isPermissionGranted("android.permission.READ_CALL_LOG", p.packageName)
                || isPermissionGranted("android.permission.WRITE_CALL_LOG", p.packageName)) {
            out.add(new ScanFinding(
                    ScanFinding.Level.MEDIUM, "Acesso ao histórico de chamadas",
                    "O aplicativo possui acesso operacional ao registro de chamadas",
                    p.packageName, 4, "Revise a permissão caso a função não exija chamadas"));
        }

        boolean contacts = isPermissionGranted("android.permission.READ_CONTACTS", p.packageName)
                || isPermissionGranted("android.permission.WRITE_CONTACTS", p.packageName);
        if (contacts) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW, "Acesso a contatos",
                    "O aplicativo possui acesso operacional à agenda de contatos",
                    p.packageName, 2,
                    "Confirme se a função do aplicativo realmente precisa dos seus contatos"));
        }

        boolean location = isPermissionGranted("android.permission.ACCESS_FINE_LOCATION", p.packageName)
                || isPermissionGranted("android.permission.ACCESS_COARSE_LOCATION", p.packageName);
        if (location) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW, "Acesso à localização",
                    "O aplicativo possui acesso operacional à localização do dispositivo",
                    p.packageName, 2,
                    "Revise a permissão e prefira localização aproximada quando suficiente"));
        }

        if (isPermissionGranted("android.permission.READ_PHONE_STATE", p.packageName)) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW, "Acesso ao estado do telefone",
                    "O aplicativo possui acesso operacional a informações do estado da telefonia",
                    p.packageName, 2,
                    "Confirme se essa permissão é necessária para a função esperada"));
        }

        if (isPermissionGranted("android.permission.REQUEST_INSTALL_PACKAGES", p.packageName)) {
            out.add(new ScanFinding(
                    ScanFinding.Level.MEDIUM, "Pode solicitar instalação de APKs",
                    "O aplicativo tem acesso operacional à capacidade de solicitar instalações",
                    p.packageName, 4,
                    "Verifique se a instalação de APKs faz parte da função esperada"));
        }

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
            boolean corroborated = sensitive >= 2
                    || isPermissionGranted("android.permission.SYSTEM_ALERT_WINDOW", p.packageName)
                    || hasAccessibilityService(p);
            out.add(new ScanFinding(
                    corroborated ? ScanFinding.Level.MEDIUM : ScanFinding.Level.LOW,
                    "Indicador heurístico de acesso remoto",
                    "Nome do app/pacote contém um marcador associado a suporte ou acesso remoto; isso sozinho não prova malware",
                    p.packageName, corroborated ? 4 : 1,
                    "Confirme se você instalou e reconhece este aplicativo"));
        }

        if (!system) {
            String installer = getInstaller(p.packageName);
            if (installer == null || installer.trim().isEmpty()) {
                out.add(new ScanFinding(
                        ScanFinding.Level.LOW, "Origem de instalação não identificada",
                        "O Android não informou um instalador conhecido para este aplicativo",
                        p.packageName, 1,
                        "Confirme a origem do APK se você não reconhecer o app"));
            }
        }

        if (debuggable && !system) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW, "Aplicativo debuggable",
                    label + " está marcado como debuggable",
                    p.packageName, 1,
                    "Normal em apps de teste; confirme a origem se não for esperado"));
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
            out.addAll(StaticApkAnalyzer.analyze(ai.sourceDir, p.packageName));
        }
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
                if (TextUtils.isEmpty(provider.readPermission)
                        && TextUtils.isEmpty(provider.writePermission)) {
                    unprotectedProviders++;
                }
            }
        }

        int unprotected = unprotectedActivities + unprotectedServices
                + unprotectedReceivers + unprotectedProviders;
        int total = exportedActivities + exportedServices + exportedReceivers + exportedProviders;
        if (total == 0) return;

        if (unprotected > 0) {
            out.add(new ScanFinding(
                    ScanFinding.Level.LOW,
                    "Componentes exportados sem permissão explícita",
                    "Activities: " + exportedActivities + " (" + unprotectedActivities + " sem proteção); "
                            + "serviços: " + exportedServices + " (" + unprotectedServices + " sem proteção); "
                            + "receivers: " + exportedReceivers + " (" + unprotectedReceivers + " sem proteção); "
                            + "providers: " + exportedProviders + " (" + unprotectedProviders + " sem proteção). "
                            + "Essa configuração pode ser legítima, mas amplia a superfície acessível por outros apps.",
                    p.packageName, 1,
                    "Revise os componentes exportados se o aplicativo não deveria expor funcionalidades a outros apps"));
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

    private boolean isPermissionGranted(String permission, String packageName) {
        try {
            String op = AppOpsManager.permissionToOp(permission);
            if (op != null) {
                ApplicationInfo ai = pm.getApplicationInfo(packageName, 0);
                AppOpsManager appOps =
                        (AppOpsManager) c.getSystemService(Context.APP_OPS_SERVICE);
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
    }

    private void checkAccessibility(List<ScanFinding> out) {
        AccessibilityManager am =
                (AccessibilityManager) c.getSystemService(Context.ACCESSIBILITY_SERVICE);
        if (am == null) return;

        List<AccessibilityServiceInfo> enabled =
                am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK);

        if (enabled.isEmpty()) {
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
                            : "Abra Acessibilidade e confirme se você o ativou conscientemente"));
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
                        "Confirme se este aplicativo precisa ler notificações do dispositivo"));
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
                            "Revise em Configurações > Segurança/Administradores do dispositivo"));

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
                                "Confirme se este gerenciamento corporativo ou de perfil foi autorizado por você"));
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
            byte[] certBytes;
            if (Build.VERSION.SDK_INT >= 28) {
                if (p.signingInfo == null) return null;
                android.content.pm.Signature[] sigs =
                        p.signingInfo.hasMultipleSigners()
                                ? p.signingInfo.getApkContentsSigners()
                                : p.signingInfo.getSigningCertificateHistory();
                if (sigs == null || sigs.length == 0) return null;
                certBytes = sigs[0].toByteArray();
            } else {
                if (p.signatures == null || p.signatures.length == 0) return null;
                certBytes = p.signatures[0].toByteArray();
            }
            return sha256(certBytes);
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
