package com.darkshield.security.analysis;

import com.darkshield.security.ScanFinding;
import org.junit.Test;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ThreatCorrelationEngineTest {
    private ScanFinding f(String title, ScanFinding.Level level) {
        return new ScanFinding(level, title, "detail", "com.example.suspect", 1, "action");
    }

    @Test public void correlatesRemoteAccessibilityAndOverlay() {
        List<ScanFinding> out = ThreatCorrelationEngine.correlate(Arrays.asList(
                f("Indicador heurístico de acesso remoto", ScanFinding.Level.LOW),
                f("Serviço de acessibilidade ativo", ScanFinding.Level.HIGH),
                f("Permissão de sobreposição concedida", ScanFinding.Level.MEDIUM)));

        assertEquals(1, out.size());
        assertEquals(ScanFinding.Level.HIGH, out.get(0).level);
        assertTrue(out.get(0).title.contains("Correlação"));
    }

    @Test public void declaredAccessibilityAloneDoesNotTriggerHighCorrelation() {
        List<ScanFinding> out = ThreatCorrelationEngine.correlate(Arrays.asList(
                f("Indicador heurístico de acesso remoto", ScanFinding.Level.LOW),
                f("Serviço de acessibilidade declarado", ScanFinding.Level.MEDIUM),
                f("Permissão de sobreposição concedida", ScanFinding.Level.LOW)));

        assertEquals(1, out.size());
        assertEquals(ScanFinding.Level.MEDIUM, out.get(0).level);
    }

    @Test public void correlatesAdministratorAndAccessibility() {
        List<ScanFinding> out = ThreatCorrelationEngine.correlate(Arrays.asList(
                f("Administrador do dispositivo ativo", ScanFinding.Level.HIGH),
                f("Serviço de acessibilidade ativo", ScanFinding.Level.HIGH)));

        assertEquals(1, out.size());
        assertEquals(ScanFinding.Level.HIGH, out.get(0).level);
    }

    @Test public void correlatesRemoteAccessWithLocation() {
        List<ScanFinding> out = ThreatCorrelationEngine.correlate(Arrays.asList(
                f("Indicador heurístico de acesso remoto", ScanFinding.Level.LOW),
                f("Acesso à localização", ScanFinding.Level.LOW)));

        assertEquals(1, out.size());
        assertEquals(ScanFinding.Level.MEDIUM, out.get(0).level);
        assertTrue(out.get(0).title.contains("dado sensível"));
    }

    @Test public void correlatesRemoteAccessWithUsageAccess() {
        List<ScanFinding> out = ThreatCorrelationEngine.correlate(Arrays.asList(
                f("Indicador heurístico de acesso remoto", ScanFinding.Level.LOW),
                f("Acesso aos dados de uso", ScanFinding.Level.MEDIUM)));

        assertEquals(1, out.size());
        assertEquals(ScanFinding.Level.MEDIUM, out.get(0).level);
        assertTrue(out.get(0).title.contains("dado sensível"));
    }

    @Test public void correlatesRemoteAccessWithNotifications() {
        List<ScanFinding> out = ThreatCorrelationEngine.correlate(Arrays.asList(
                f("Indicador heurístico de acesso remoto", ScanFinding.Level.LOW),
                f("Acesso a notificações ativo", ScanFinding.Level.MEDIUM)));

        assertEquals(1, out.size());
        assertEquals(ScanFinding.Level.MEDIUM, out.get(0).level);
        assertTrue(out.get(0).title.contains("notificações"));
    }

    @Test public void correlatesRemoteAccessWithBootPersistence() {
        List<ScanFinding> out = ThreatCorrelationEngine.correlate(Arrays.asList(
                f("Indicador heurístico de acesso remoto", ScanFinding.Level.LOW),
                f("Inicialização automática declarada", ScanFinding.Level.LOW)));

        assertEquals(1, out.size());
        assertEquals(ScanFinding.Level.MEDIUM, out.get(0).level);
        assertTrue(out.get(0).title.contains("inicialização automática"));
    }

    @Test public void correlatesRemoteAccessWithApkInstallCapability() {
        List<ScanFinding> out = ThreatCorrelationEngine.correlate(Arrays.asList(
                f("Indicador heurístico de acesso remoto", ScanFinding.Level.LOW),
                f("Pode solicitar instalação de APKs", ScanFinding.Level.MEDIUM)));

        assertEquals(1, out.size());
        assertEquals(ScanFinding.Level.MEDIUM, out.get(0).level);
        assertTrue(out.get(0).title.contains("instalação de APK"));
    }

    @Test public void correlatesAccessibilityOverlayAndBootWithoutRemoteMarker() {
        List<ScanFinding> out = ThreatCorrelationEngine.correlate(Arrays.asList(
                f("Serviço de acessibilidade ativo", ScanFinding.Level.HIGH),
                f("Permissão de sobreposição concedida", ScanFinding.Level.LOW),
                f("Inicialização automática declarada", ScanFinding.Level.LOW)));

        assertEquals(1, out.size());
        assertEquals(ScanFinding.Level.HIGH, out.get(0).level);
        assertTrue(out.get(0).title.contains("acessibilidade"));
    }

    @Test public void correlatesActiveAccessibilityWithNotifications() {
        List<ScanFinding> out = ThreatCorrelationEngine.correlate(Arrays.asList(
                f("Serviço de acessibilidade ativo", ScanFinding.Level.HIGH),
                f("Acesso a notificações ativo", ScanFinding.Level.MEDIUM)));

        assertEquals(1, out.size());
        assertEquals(ScanFinding.Level.MEDIUM, out.get(0).level);
        assertTrue(out.get(0).title.contains("acessibilidade"));
    }

    @Test public void correlatesAccessibilityNotificationsAndBootWithoutRemoteMarker() {
        List<ScanFinding> out = ThreatCorrelationEngine.correlate(Arrays.asList(
                f("Serviço de acessibilidade ativo", ScanFinding.Level.HIGH),
                f("Acesso a notificações ativo", ScanFinding.Level.MEDIUM),
                f("Inicialização automática declarada", ScanFinding.Level.LOW)));

        assertEquals(1, out.size());
        assertEquals(ScanFinding.Level.HIGH, out.get(0).level);
        assertTrue(out.get(0).title.contains("notificações"));
    }

    @Test public void strongAccessibilityCorrelationAvoidsDuplicateNotificationFinding() {
        List<ScanFinding> out = ThreatCorrelationEngine.correlate(Arrays.asList(
                f("Serviço de acessibilidade ativo", ScanFinding.Level.HIGH),
                f("Acesso a notificações ativo", ScanFinding.Level.MEDIUM),
                f("Permissão de sobreposição concedida", ScanFinding.Level.LOW),
                f("Inicialização automática declarada", ScanFinding.Level.LOW)));

        assertEquals(1, out.size());
        assertEquals(ScanFinding.Level.HIGH, out.get(0).level);
        assertTrue(out.get(0).title.contains("sobreposição"));
    }

    @Test public void doesNotCorrelateAcrossPackages() {
        ScanFinding remote = new ScanFinding(ScanFinding.Level.LOW,
                "Indicador heurístico de acesso remoto", "detail", "com.example.remote", 1, null);
        ScanFinding access = new ScanFinding(ScanFinding.Level.MEDIUM,
                "Serviço de acessibilidade declarado", "detail", "com.example.access", 1, null);

        assertTrue(ThreatCorrelationEngine.correlate(Arrays.asList(remote, access)).isEmpty());
    }

    @Test public void correlationOrderIsDeterministicForHashCollidingPackages() {
        List<ScanFinding> firstInput = Arrays.asList(
                new ScanFinding(ScanFinding.Level.LOW,
                        "Indicador heurístico de acesso remoto", "detail",
                        "com.example.FB", 1, null),
                new ScanFinding(ScanFinding.Level.MEDIUM,
                        "Acesso a notificações ativo", "detail",
                        "com.example.FB", 1, null),
                new ScanFinding(ScanFinding.Level.LOW,
                        "Indicador heurístico de acesso remoto", "detail",
                        "com.example.Ea", 1, null),
                new ScanFinding(ScanFinding.Level.MEDIUM,
                        "Acesso a notificações ativo", "detail",
                        "com.example.Ea", 1, null));

        List<ScanFinding> secondInput = Arrays.asList(
                firstInput.get(2), firstInput.get(3),
                firstInput.get(0), firstInput.get(1));

        List<ScanFinding> first = ThreatCorrelationEngine.correlate(firstInput);
        List<ScanFinding> second = ThreatCorrelationEngine.correlate(secondInput);

        assertEquals(2, first.size());
        assertEquals(2, second.size());
        assertEquals("com.example.Ea", first.get(0).packageName);
        assertEquals("com.example.FB", first.get(1).packageName);
        assertEquals(first.get(0).packageName, second.get(0).packageName);
        assertEquals(first.get(1).packageName, second.get(1).packageName);
        assertEquals(first.get(0).title, second.get(0).title);
        assertEquals(first.get(1).title, second.get(1).title);
    }
    @Test public void keepsOnlyStrongestCorrelationPerPackage() {
        List<ScanFinding> out = ThreatCorrelationEngine.correlate(Arrays.asList(
                f("Indicador heurístico de acesso remoto", ScanFinding.Level.LOW),
                f("Serviço de acessibilidade ativo", ScanFinding.Level.HIGH),
                f("Permissão de sobreposição concedida", ScanFinding.Level.MEDIUM),
                f("Acesso a notificações ativo", ScanFinding.Level.MEDIUM),
                f("Administrador do dispositivo ativo", ScanFinding.Level.HIGH)));

        assertEquals(1, out.size());
        assertEquals(ScanFinding.Level.HIGH, out.get(0).level);
        assertEquals(7, out.get(0).points);
        assertTrue(out.get(0).title.contains("Correlação de administrador e acessibilidade")
                || out.get(0).title.contains("Correlação de controle remoto"));
    }

}
