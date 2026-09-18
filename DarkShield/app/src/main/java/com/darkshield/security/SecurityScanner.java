package com.darkshield.security;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.accessibility.AccessibilityManager;
import java.security.MessageDigest;
import java.util.*;

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
        "anydesk","teamviewer","airdroid","rustdesk","splashtop","vysor","scrcpy","remote","remotecontrol","remote support","support","control"
    ));
    private final Context c;
    private final PackageManager pm;

    public SecurityScanner(Context c) { this.c=c.getApplicationContext(); this.pm=c.getPackageManager(); }

    public List<ScanFinding> scan() {
        List<ScanFinding> out=new ArrayList<>();
        addBaseline(out);
        List<PackageInfo> apps=getApps();
        out.add(new ScanFinding(ScanFinding.Level.INFO,"Aplicativos analisados",
                apps.size()+" pacote(s) visíveis para o scanner",null,0,null));
        for(PackageInfo p:apps) inspectApp(p,out);
        checkAccessibility(out); checkNotificationListeners(out); checkDeviceAdmins(out);
        return out;
    }

    private List<PackageInfo> getApps() {
        int flags=PackageManager.GET_PERMISSIONS|PackageManager.GET_SERVICES;
        if(Build.VERSION.SDK_INT>=28) flags|=PackageManager.GET_SIGNING_CERTIFICATES; else flags|=PackageManager.GET_SIGNATURES;
        try {
            if(Build.VERSION.SDK_INT>=33) return pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags));
            return pm.getInstalledPackages(flags);
        } catch(Exception e) { return Collections.emptyList(); }
    }

    private void inspectApp(PackageInfo p,List<ScanFinding> out) {
        ApplicationInfo ai=p.applicationInfo;
        if(ai==null||c.getPackageName().equals(p.packageName)) return;
        String label=safeLabel(ai);
        String lower=(label+" "+p.packageName).toLowerCase(Locale.ROOT);
        Set<String> ps=new HashSet<>();
        if(p.requestedPermissions!=null) Collections.addAll(ps,p.requestedPermissions);
        int sensitive=0; for(String permission:SENSITIVE_PERMISSIONS) if(ps.contains(permission)) sensitive++;
        boolean system=isSystemApp(ai), remoteMarker=containsRemoteControlMarker(lower);
        boolean sideLoad=isOutsideUsualSystemArea(ai), debuggable=(ai.flags&ApplicationInfo.FLAG_DEBUGGABLE)!=0;

        if(ps.contains("android.permission.SYSTEM_ALERT_WINDOW"))
            out.add(new ScanFinding(sideLoad?ScanFinding.Level.MEDIUM:ScanFinding.Level.LOW,"Permissão de sobreposição",label,p.packageName,sideLoad?4:2,"Revisar em Configurações > Apps > Acesso especial"));
        int mediaCount=0; if(ps.contains("android.permission.RECORD_AUDIO")) mediaCount++; if(ps.contains("android.permission.CAMERA")) mediaCount++;
        if(mediaCount>0) out.add(new ScanFinding(ScanFinding.Level.LOW,"Acesso a microfone/câmera",label+" solicita "+mediaCount+" recurso(s) de áudio/vídeo",p.packageName,1,"Confirme se essa função é necessária"));
        if(ps.contains("android.permission.READ_SMS")||ps.contains("android.permission.RECEIVE_SMS")||ps.contains("android.permission.SEND_SMS"))
            out.add(new ScanFinding(ScanFinding.Level.MEDIUM,"Acesso a SMS","O aplicativo declara acesso a mensagens SMS",p.packageName,4,"Revisar a permissão e a finalidade do aplicativo"));
        if(ps.contains("android.permission.READ_CALL_LOG")||ps.contains("android.permission.WRITE_CALL_LOG"))
            out.add(new ScanFinding(ScanFinding.Level.MEDIUM,"Acesso ao histórico de chamadas","O aplicativo declara acesso ao registro de chamadas",p.packageName,4,"Revise a permissão caso a função não exija chamadas"));
        if(ps.contains("android.permission.REQUEST_INSTALL_PACKAGES"))
            out.add(new ScanFinding(ScanFinding.Level.MEDIUM,"Pode solicitar instalação de APKs","O aplicativo declara a capacidade de solicitar instalações",p.packageName,4,"Verifique se a instalação de APKs faz parte da função esperada"));
        if(hasAccessibilityService(p)) {
            ScanFinding.Level lvl=system?ScanFinding.Level.INFO:ScanFinding.Level.MEDIUM; int points=system?0:5;
            out.add(new ScanFinding(lvl,"Serviço de acessibilidade declarado",system?label+" é um app de sistema":label+" possui um serviço que pode interagir com a interface",p.packageName,points,"Verifique se é um serviço que você reconhece"));
        }
        if(remoteMarker) {
            boolean corroborated=sensitive>=2||ps.contains("android.permission.SYSTEM_ALERT_WINDOW")||hasAccessibilityService(p);
            out.add(new ScanFinding(corroborated?ScanFinding.Level.MEDIUM:ScanFinding.Level.LOW,"Indicador heurístico de acesso remoto","Nome do app/pacote contém um marcador associado a suporte ou acesso remoto; isso sozinho não prova malware",p.packageName,corroborated?4:1,"Confirme se você instalou e reconhece este aplicativo"));
        }
        if(sideLoad&&!system) {
            String installer=getInstaller(p.packageName);
            out.add(new ScanFinding(ScanFinding.Level.LOW,"Aplicativo instalado em área de usuário",installer==null?"Origem de instalação não identificada":"Instalador: "+installer,p.packageName,1,"Verifique a origem do APK se você não reconhecer o app"));
        }
        if(debuggable&&!system)
            out.add(new ScanFinding(ScanFinding.Level.LOW,"Aplicativo debuggable",label+" está marcado como debuggable",p.packageName,1,"Normal em apps de teste; confirme a origem se não for esperado"));
        String cert=signingSha256(p); if(cert!=null) out.add(new ScanFinding(ScanFinding.Level.INFO,"Assinatura SHA-256",cert,p.packageName,0,null));
    }

    private boolean hasAccessibilityService(PackageInfo p) {
        if(p.services==null) return false;
        for(ServiceInfo s:p.services) if("android.permission.BIND_ACCESSIBILITY_SERVICE".equals(s.permission)) return true;
        return false;
    }
    private boolean containsRemoteControlMarker(String s) { for(String marker:REMOTE_MARKERS) if(s.contains(marker)) return true; return false; }
    private boolean isSystemApp(ApplicationInfo ai) { return (ai.flags&ApplicationInfo.FLAG_SYSTEM)!=0||(ai.flags&ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)!=0; }
    private boolean isOutsideUsualSystemArea(ApplicationInfo ai) {
        String path=ai.sourceDir==null?"":ai.sourceDir;
        return path.startsWith("/data/app/")||path.startsWith("/mnt/expand/")||path.startsWith("/data/user/");
    }
    private String safeLabel(ApplicationInfo ai) { try{return String.valueOf(pm.getApplicationLabel(ai));}catch(Exception e){return ai.packageName;} }
    private String getInstaller(String packageName) {
        try { if(Build.VERSION.SDK_INT>=30) return pm.getInstallSourceInfo(packageName).getInstallingPackageName(); return pm.getInstallerPackageName(packageName); }
        catch(Exception e){return null;}
    }

    private void addBaseline(List<ScanFinding> out) {
        int dev=0,adb=0;
        try{dev=Settings.Global.getInt(c.getContentResolver(),Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,0);}catch(Exception ignored){}
        try{adb=Settings.Global.getInt(c.getContentResolver(),Settings.Global.ADB_ENABLED,0);}catch(Exception ignored){}
        out.add(new ScanFinding(dev==1?ScanFinding.Level.INFO:ScanFinding.Level.LOW,"Opções do desenvolvedor",dev==1?"Ativadas":"Desativadas",null,dev==1?0:1,dev==1?null:"Opcional; o modo desenvolvedor não é, por si só, uma invasão"));
        out.add(new ScanFinding(adb==1?ScanFinding.Level.MEDIUM:ScanFinding.Level.INFO,"Depuração USB (ADB)",adb==1?"Ativada":"Desativada",null,adb==1?4:0,adb==1?"Desative quando não estiver usando ADB":null));
    }

    private void checkAccessibility(List<ScanFinding> out) {
        AccessibilityManager am=(AccessibilityManager)c.getSystemService(Context.ACCESSIBILITY_SERVICE); if(am==null)return;
        List<AccessibilityServiceInfo> enabled=am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
        if(enabled.isEmpty()){out.add(new ScanFinding(ScanFinding.Level.INFO,"Serviços de acessibilidade ativos","Nenhum serviço de terceiros retornado como ativo",null,0,null));return;}
        for(AccessibilityServiceInfo info:enabled){
            ComponentName cn=null; try{cn=info.getResolveInfo().serviceInfo.getComponentName();}catch(Exception ignored){}
            String pkg=cn==null?null:cn.getPackageName(); boolean system=pkg!=null&&isSystemPackage(pkg);
            out.add(new ScanFinding(system?ScanFinding.Level.LOW:ScanFinding.Level.HIGH,"Serviço de acessibilidade ativo",cn==null?"Serviço ativo detectado":cn.flattenToShortString(),pkg,system?1:8,system?"Revise apenas se não reconhecer o componente":"Abra Acessibilidade e confirme se você o ativou conscientemente"));
        }
    }
    private boolean isSystemPackage(String pkg){try{return isSystemApp(pm.getApplicationInfo(pkg,0));}catch(Exception e){return false;}}
    private void checkNotificationListeners(List<ScanFinding> out) {
        try {
            String v=Settings.Secure.getString(c.getContentResolver(),"enabled_notification_listeners");
            if(TextUtils.isEmpty(v)) out.add(new ScanFinding(ScanFinding.Level.INFO,"Acesso a notificações","Nenhum listener ativo",null,0,null));
            else {String[] entries=v.split(":");out.add(new ScanFinding(ScanFinding.Level.MEDIUM,"Apps com acesso a notificações",entries.length+" componente(s) ativo(s): "+v,null,3,"Revise em Configurações > Acesso a notificações"));}
        } catch(Exception e){out.add(new ScanFinding(ScanFinding.Level.LOW,"Acesso a notificações","Não foi possível consultar",null,1,null));}
    }
    private void checkDeviceAdmins(List<ScanFinding> out) {
        DevicePolicyManager dpm=(DevicePolicyManager)c.getSystemService(Context.DEVICE_POLICY_SERVICE); if(dpm==null)return;
        try {
            List<ComponentName> admins=dpm.getActiveAdmins();
            if(admins==null||admins.isEmpty()) out.add(new ScanFinding(ScanFinding.Level.INFO,"Administradores do dispositivo","Nenhum administrador ativo",null,0,null));
            else for(ComponentName n:admins){String pkg=n.getPackageName();boolean system=isSystemPackage(pkg);out.add(new ScanFinding(system?ScanFinding.Level.LOW:ScanFinding.Level.HIGH,"Administrador do dispositivo ativo",n.flattenToShortString(),pkg,system?1:8,"Revise em Configurações > Segurança/Administradores do dispositivo"));}
        } catch(SecurityException e){out.add(new ScanFinding(ScanFinding.Level.LOW,"Administradores do dispositivo","A consulta foi restringida pelo sistema",null,1,null));}
    }
    private String signingSha256(PackageInfo p) {
        try {
            byte[] certBytes;
            if(Build.VERSION.SDK_INT>=28){
                if(p.signingInfo==null)return null;
                android.content.pm.Signature[] sigs=p.signingInfo.hasMultipleSigners()?p.signingInfo.getApkContentsSigners():p.signingInfo.getSigningCertificateHistory();
                if(sigs==null||sigs.length==0)return null; certBytes=sigs[0].toByteArray();
            } else { if(p.signatures==null||p.signatures.length==0)return null; certBytes=p.signatures[0].toByteArray(); }
            return sha256(certBytes);
        } catch(Exception e){return null;}
    }
    private String sha256(byte[] bytes){
        try{MessageDigest d=MessageDigest.getInstance("SHA-256");byte[] digest=d.digest(bytes);StringBuilder sb=new StringBuilder();for(byte x:digest)sb.append(String.format(Locale.ROOT,"%02X",x));return sb.toString();}
        catch(Exception e){return null;}
    }
}