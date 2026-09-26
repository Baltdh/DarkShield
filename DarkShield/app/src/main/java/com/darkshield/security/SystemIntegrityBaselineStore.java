package com.darkshield.security;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class SystemIntegrityBaselineStore {
    public static final String ATTR_ROOT_BINARY = "integrity.root_binary";
    public static final String ATTR_TEST_KEYS = "integrity.test_keys";
    public static final String ATTR_DEBUGGABLE_BUILD = "integrity.debuggable_build";
    public static final String ATTR_ROOT_MANAGER = "integrity.root_manager";
    public static final String ATTR_CHANGE_ROOT_BINARY = "integrity.change_root_binary";
    public static final String ATTR_CHANGE_TEST_KEYS = "integrity.change_test_keys";
    public static final String ATTR_CHANGE_DEBUGGABLE = "integrity.change_debuggable";
    public static final String ATTR_CHANGE_ROOT_MANAGER = "integrity.change_root_manager";

    private static final String PREFS = "darkshield_system_integrity_baseline";
    private static final String KEY_SCHEMA = "schema";
    private static final String KEY_DATA = "data";
    private static final int SCHEMA_VERSION = 1;

    static final class Snapshot {
        final Map<String, String> values;

        Snapshot(Map<String, String> values) {
            Map<String, String> copy = new HashMap<>();
            if (values != null) {
                for (Map.Entry<String, String> entry : values.entrySet()) {
                    if (entry == null || entry.getKey() == null || entry.getValue() == null) continue;
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

    private static final class Loaded {
        final boolean present;
        final Snapshot snapshot;

        Loaded(boolean present, Snapshot snapshot) {
            this.present = present;
            this.snapshot = snapshot;
        }
    }

    private SystemIntegrityBaselineStore() {}

    public static List<ScanFinding> compareAndUpdate(
            Context context, List<ScanFinding> findings) {
        if (context == null) return Collections.emptyList();
        Context appContext = context.getApplicationContext();
        Loaded previous = load(appContext);
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
            copy(finding, values, ATTR_ROOT_BINARY);
            copy(finding, values, ATTR_TEST_KEYS);
            copy(finding, values, ATTR_DEBUGGABLE_BUILD);
            copy(finding, values, ATTR_ROOT_MANAGER);
        }
        return new Snapshot(values);
    }

    static List<ScanFinding> compare(Snapshot before, Snapshot now) {
        if (before == null || now == null) return Collections.emptyList();
        List<ScanFinding> out = new ArrayList<>();

        addEmergence(
                out, before, now, ATTR_ROOT_BINARY,
                ScanFinding.Level.HIGH,
                7,
                "Binário de root surgiu desde a última verificação",
                "Um caminho conhecido de binário su não estava presente na linha de base anterior e agora foi observado.",
                "Revise alterações de root realizadas desde a última verificação",
                ATTR_CHANGE_ROOT_BINARY);

        addEmergence(
                out, before, now, ATTR_ROOT_MANAGER,
                ScanFinding.Level.MEDIUM,
                5,
                "Marcador de gerenciamento de root surgiu",
                "Marcadores observáveis de Magisk/KernelSU ou estado semelhante não estavam presentes e agora foram detectados.",
                "Confirme se você instalou ou ativou conscientemente uma solução de root",
                ATTR_CHANGE_ROOT_MANAGER);

        addEmergence(
                out, before, now, ATTR_TEST_KEYS,
                ScanFinding.Level.MEDIUM,
                3,
                "Build passou a reportar test-keys",
                "A linha de base anterior não reportava test-keys e o sistema atual passou a reportá-las.",
                "Confirme se houve troca, downgrade ou reinstalação intencional da ROM",
                ATTR_CHANGE_TEST_KEYS);

        addEmergence(
                out, before, now, ATTR_DEBUGGABLE_BUILD,
                ScanFinding.Level.MEDIUM,
                3,
                "Build passou a ser eng/userdebug",
                "O tipo de build observado mudou para um perfil de desenvolvimento desde a linha de base anterior.",
                "Confirme se a mudança de firmware foi intencional",
                ATTR_CHANGE_DEBUGGABLE);

        return out;
    }

    static String encode(Snapshot snapshot) {
        if (snapshot == null || snapshot.values.isEmpty()) return "";
        List<String> keys = new ArrayList<>(snapshot.values.keySet());
        Collections.sort(keys);
        StringBuilder out = new StringBuilder();
        for (String key : keys) {
            String value = snapshot.values.get(key);
            if (key == null || value == null
                    || key.indexOf('\n') >= 0 || key.indexOf('\t') >= 0
                    || value.indexOf('\n') >= 0 || value.indexOf('\t') >= 0) {
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
        for (String line : encoded.split("\n")) {
            int separator = line.indexOf('\t');
            if (separator <= 0 || separator >= line.length() - 1) continue;
            values.put(line.substring(0, separator), line.substring(separator + 1));
        }
        return new Snapshot(values);
    }

    private static void addEmergence(
            List<ScanFinding> out,
            Snapshot before,
            Snapshot now,
            String key,
            ScanFinding.Level level,
            int points,
            String title,
            String detail,
            String action,
            String changeAttribute) {
        if (!"0".equals(before.get(key)) || !"1".equals(now.get(key))) return;
        out.add(new ScanFinding(level, title, detail, null, points, action)
                .withEvidence(
                        ScanFinding.EvidenceSource.DERIVED,
                        ScanFinding.EvidenceTag.CORRELATION)
                .withAttribute(changeAttribute, "1"));
    }

    private static void copy(
            ScanFinding finding, Map<String, String> destination, String key) {
        String value = finding.attribute(key);
        if (value != null) destination.put(key, value);
    }

    private static Loaded load(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        if (prefs.getInt(KEY_SCHEMA, -1) != SCHEMA_VERSION || !prefs.contains(KEY_DATA)) {
            return new Loaded(false, Snapshot.empty());
        }
        return new Loaded(true, decode(prefs.getString(KEY_DATA, "")));
    }

    private static void save(Context context, Snapshot snapshot) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .putInt(KEY_SCHEMA, SCHEMA_VERSION)
                .putString(KEY_DATA, encode(snapshot))
                .apply();
    }
}
