package com.darkshield.security;

import android.content.Context;
import android.content.SharedPreferences;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DevicePostureBaselineStore {
    public static final String ATTR_DEV_OPTIONS = "device.dev_options";
    public static final String ATTR_ADB = "device.adb";
    public static final String ATTR_SECURITY_PATCH = "device.security_patch";
    public static final String ATTR_DEFAULT_IME = "device.default_ime";
    public static final String ATTR_DEFAULT_SMS = "device.default_sms";
    public static final String ATTR_DEFAULT_DIALER = "device.default_dialer";
    public static final String ATTR_CHANGE_ADB_ENABLED = "posture.change_adb_enabled";
    public static final String ATTR_CHANGE_DEV_ENABLED = "posture.change_dev_enabled";
    public static final String ATTR_CHANGE_PATCH_REGRESSED = "posture.change_patch_regressed";
    public static final String ATTR_CHANGE_HANDLER = "posture.change_handler";

    private static final String PREFS = "darkshield_device_posture_baseline";
    private static final String KEY_SCHEMA = "schema";
    private static final String KEY_DATA = "data";
    private static final int SCHEMA_VERSION = 1;

    static final class Snapshot {
        final Map<String, String> values;

        Snapshot(Map<String, String> values) {
            Map<String, String> copy = new HashMap<>();
            if (values != null) {
                for (Map.Entry<String, String> entry : values.entrySet()) {
                    if (entry == null
                            || entry.getKey() == null
                            || entry.getKey().trim().isEmpty()
                            || entry.getValue() == null) {
                        continue;
                    }
                    copy.put(entry.getKey(), entry.getValue());
                }
            }
            this.values = Collections.unmodifiableMap(copy);
        }

        String get(String key) {
            String value = values.get(key);
            return value == null ? "" : value;
        }

        static Snapshot empty() {
            return new Snapshot(Collections.emptyMap());
        }
    }

    private static final class LoadedBaseline {
        final boolean present;
        final Snapshot snapshot;

        LoadedBaseline(boolean present, Snapshot snapshot) {
            this.present = present;
            this.snapshot = snapshot;
        }
    }

    private DevicePostureBaselineStore() {}

    public static List<ScanFinding> compareAndUpdate(
            Context context, List<ScanFinding> findings) {
        if (context == null) return Collections.emptyList();

        Context appContext = context.getApplicationContext();
        LoadedBaseline previous = load(appContext);
        Snapshot current = fromFindings(findings);
        List<ScanFinding> changes = previous.present
                ? compare(previous.snapshot, current)
                : Collections.emptyList();
        save(appContext, current);
        return changes;
    }

    public static void clear(Context context) {
        if (context == null) return;
        context.getApplicationContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .apply();
    }

    static Snapshot fromFindings(List<ScanFinding> findings) {
        Map<String, String> values = new HashMap<>();
        if (findings == null) return new Snapshot(values);

        for (ScanFinding finding : findings) {
            if (finding == null || finding.attributes == null) continue;
            copyIfPresent(finding, values, ATTR_DEV_OPTIONS);
            copyIfPresent(finding, values, ATTR_ADB);
            copyIfPresent(finding, values, ATTR_SECURITY_PATCH);
            copyIfPresent(finding, values, ATTR_DEFAULT_IME);
            copyIfPresent(finding, values, ATTR_DEFAULT_SMS);
            copyIfPresent(finding, values, ATTR_DEFAULT_DIALER);
        }
        return new Snapshot(values);
    }

    static List<ScanFinding> compare(Snapshot before, Snapshot now) {
        if (before == null || now == null) return Collections.emptyList();
        List<ScanFinding> changes = new ArrayList<>();

        boolean adbEnabled = "0".equals(before.get(ATTR_ADB))
                && "1".equals(now.get(ATTR_ADB));
        boolean devEnabled = "0".equals(before.get(ATTR_DEV_OPTIONS))
                && "1".equals(now.get(ATTR_DEV_OPTIONS));

        if (adbEnabled) {
            changes.add(new ScanFinding(
                    ScanFinding.Level.MEDIUM,
                    "ADB foi ativado desde a última verificação",
                    devEnabled
                            ? "A depuração ADB e as Opções do desenvolvedor passaram de desativadas para ativadas."
                            : "A depuração ADB passou de desativada para ativada.",
                    null,
                    4,
                    "Se você não ativou ADB conscientemente, desative a depuração e revise os aplicativos com acesso elevado")
                    .withEvidence(
                            ScanFinding.EvidenceSource.DERIVED,
                            ScanFinding.EvidenceTag.CORRELATION)
                    .withAttribute(ATTR_CHANGE_ADB_ENABLED, "1")
                    .withAttribute(ATTR_CHANGE_DEV_ENABLED, devEnabled ? "1" : "0"));
        } else if (devEnabled) {
            changes.add(new ScanFinding(
                    ScanFinding.Level.LOW,
                    "Opções do desenvolvedor foram ativadas",
                    "As Opções do desenvolvedor passaram de desativadas para ativadas desde a última verificação.",
                    null,
                    1,
                    "Confirme se essa mudança foi intencional")
                    .withEvidence(ScanFinding.EvidenceSource.DERIVED)
                    .withAttribute(ATTR_CHANGE_DEV_ENABLED, "1"));
        }

        if (patchRegressed(
                before.get(ATTR_SECURITY_PATCH),
                now.get(ATTR_SECURITY_PATCH))) {
            changes.add(new ScanFinding(
                    ScanFinding.Level.HIGH,
                    "Nível do patch de segurança regrediu",
                    "O Android agora informa patch " + now.get(ATTR_SECURITY_PATCH)
                            + ", anterior ao patch " + before.get(ATTR_SECURITY_PATCH)
                            + " observado na última linha de base.",
                    null,
                    6,
                    "Confirme se houve downgrade/reinstalação do sistema e procure uma atualização oficial")
                    .withEvidence(
                            ScanFinding.EvidenceSource.DERIVED,
                            ScanFinding.EvidenceTag.VULNERABILITY,
                            ScanFinding.EvidenceTag.CORRELATION)
                    .withAttribute(ATTR_CHANGE_PATCH_REGRESSED, "1"));
        }

        addHandlerChange(
                changes,
                "Teclado padrão mudou",
                before.get(ATTR_DEFAULT_IME),
                now.get(ATTR_DEFAULT_IME),
                ScanFinding.Level.MEDIUM,
                3,
                "Confirme se você escolheu conscientemente o novo teclado; ele pode processar texto digitado",
                "ime");
        addHandlerChange(
                changes,
                "Aplicativo padrão de SMS mudou",
                before.get(ATTR_DEFAULT_SMS),
                now.get(ATTR_DEFAULT_SMS),
                ScanFinding.Level.LOW,
                1,
                "Confirme se você reconhece o novo aplicativo padrão de SMS",
                "sms");
        addHandlerChange(
                changes,
                "Aplicativo padrão de chamadas mudou",
                before.get(ATTR_DEFAULT_DIALER),
                now.get(ATTR_DEFAULT_DIALER),
                ScanFinding.Level.LOW,
                1,
                "Confirme se você reconhece o novo aplicativo padrão de chamadas",
                "dialer");

        return changes;
    }

    static boolean patchRegressed(String before, String now) {
        if (before == null || now == null
                || before.trim().isEmpty() || now.trim().isEmpty()) {
            return false;
        }
        try {
            return LocalDate.parse(now.trim()).isBefore(LocalDate.parse(before.trim()));
        } catch (DateTimeParseException e) {
            return false;
        }
    }

    static String encode(Snapshot snapshot) {
        if (snapshot == null || snapshot.values.isEmpty()) return "";
        List<String> keys = new ArrayList<>(snapshot.values.keySet());
        Collections.sort(keys);
        StringBuilder out = new StringBuilder();
        for (String key : keys) {
            String value = snapshot.values.get(key);
            if (key == null || value == null
                    || key.indexOf('\t') >= 0
                    || key.indexOf('\n') >= 0
                    || value.indexOf('\t') >= 0
                    || value.indexOf('\n') >= 0) {
                continue;
            }
            if (out.length() > 0) out.append('\n');
            out.append(key).append('\t').append(value);
        }
        return out.toString();
    }

    static Snapshot decode(String encoded) {
        Map<String, String> values = new HashMap<>();
        if (encoded == null || encoded.trim().isEmpty()) return new Snapshot(values);

        for (String line : encoded.split("\\n")) {
            if (line == null || line.isEmpty()) continue;
            int separator = line.indexOf('\t');
            if (separator <= 0 || separator >= line.length() - 1) continue;
            String key = line.substring(0, separator).trim();
            String value = line.substring(separator + 1);
            if (!key.isEmpty()) values.put(key, value);
        }
        return new Snapshot(values);
    }

    private static void addHandlerChange(
            List<ScanFinding> out,
            String title,
            String before,
            String now,
            ScanFinding.Level level,
            int points,
            String action,
            String changeValue) {
        if (before == null || now == null
                || before.trim().isEmpty() || now.trim().isEmpty()
                || before.equals(now)) {
            return;
        }
        out.add(new ScanFinding(
                level,
                title,
                "Anterior: " + before + "; atual: " + now
                        + ". A mudança pode ser legítima após uma escolha do usuário ou atualização.",
                now,
                points,
                action)
                .withEvidence(ScanFinding.EvidenceSource.DERIVED)
                .withAttribute(ATTR_CHANGE_HANDLER, changeValue == null ? "" : changeValue));
    }

    private static void copyIfPresent(
            ScanFinding finding,
            Map<String, String> destination,
            String key) {
        String value = finding.attribute(key);
        if (value != null) destination.put(key, value);
    }

    private static LoadedBaseline load(Context context) {
        SharedPreferences prefs =
                context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        if (prefs.getInt(KEY_SCHEMA, -1) != SCHEMA_VERSION
                || !prefs.contains(KEY_DATA)) {
            return new LoadedBaseline(false, Snapshot.empty());
        }
        return new LoadedBaseline(
                true,
                decode(prefs.getString(KEY_DATA, "")));
    }

    private static void save(Context context, Snapshot snapshot) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .putInt(KEY_SCHEMA, SCHEMA_VERSION)
                .putString(KEY_DATA, encode(snapshot))
                .apply();
    }
}
