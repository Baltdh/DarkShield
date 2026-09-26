package com.darkshield.security;

import android.content.Context;
import android.content.SharedPreferences;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class AppPresenceBaselineStore {
    public static final String ATTR_CHANGE_REAPPEARED = "presence.change_reappeared";
    public static final String ATTR_REAPPEAR_SIGNER_MISMATCH = "presence.reappear_signer_mismatch";
    public static final String ATTR_REAPPEAR_SIGNER_ROTATION = "presence.reappear_signer_rotation";
    public static final String ATTR_REAPPEAR_DOWNGRADE = "presence.reappear_downgrade";
    public static final String ATTR_REAPPEAR_INSTALLER_CHANGED = "presence.reappear_installer_changed";

    private static final String PREFS = "darkshield_app_presence_baseline";
    private static final String KEY_SCHEMA = "schema";
    private static final String KEY_DATA = "data";
    private static final int SCHEMA_VERSION = 1;
    private static final int MAX_TRACKED_PACKAGES = 2048;

    static final class State {
        final String packageName;
        final boolean missingAfterSeen;
        final long versionCode;
        final String installer;
        final Set<String> currentSigners;

        State(
                String packageName,
                boolean missingAfterSeen,
                long versionCode,
                String installer,
                Set<String> currentSigners) {
            this.packageName = packageName == null ? "" : packageName.trim();
            this.missingAfterSeen = missingAfterSeen;
            this.versionCode = Math.max(0L, versionCode);
            this.installer = installer == null ? "" : installer.trim();
            this.currentSigners = normalized(currentSigners);
        }
    }

    static final class Snapshot {
        final Map<String, State> states;

        Snapshot(Map<String, State> states) {
            Map<String, State> copy = new HashMap<>();
            if (states != null) {
                for (Map.Entry<String, State> entry : states.entrySet()) {
                    if (entry == null || entry.getKey() == null || entry.getValue() == null) continue;
                    if (entry.getKey().trim().isEmpty()) continue;
                    copy.put(entry.getKey(), entry.getValue());
                }
            }
            this.states = Collections.unmodifiableMap(copy);
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

    static final class UpdateResult {
        final Snapshot next;
        final List<ScanFinding> findings;

        UpdateResult(Snapshot next, List<ScanFinding> findings) {
            this.next = next;
            this.findings = Collections.unmodifiableList(new ArrayList<>(findings));
        }
    }

    private AppPresenceBaselineStore() {}

    public static List<ScanFinding> compareAndUpdate(
            Context context, List<ScanFinding> findings) {
        if (context == null) return Collections.emptyList();
        Context appContext = context.getApplicationContext();
        Loaded loaded = load(appContext);
        PackageIdentityBaselineStore.Snapshot current =
                PackageIdentityBaselineStore.fromFindings(findings);

        if (!loaded.present) {
            save(appContext, initialize(current));
            return Collections.emptyList();
        }

        UpdateResult result = update(loaded.snapshot, current);
        save(appContext, result.next);
        return result.findings;
    }

    public static void clear(Context context) {
        if (context == null) return;
        context.getApplicationContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .apply();
    }

    static Snapshot initialize(PackageIdentityBaselineStore.Snapshot current) {
        Map<String, State> states = new HashMap<>();
        if (current != null) {
            for (PackageIdentityBaselineStore.Identity identity
                    : current.byPackage.values()) {
                if (identity == null || identity.packageName.isEmpty()) continue;
                states.put(identity.packageName, fromIdentity(identity, false));
            }
        }
        return trim(new Snapshot(states));
    }

    static UpdateResult update(
            Snapshot previous,
            PackageIdentityBaselineStore.Snapshot current) {
        Map<String, State> next = new HashMap<>();
        if (previous != null) next.putAll(previous.states);

        Map<String, PackageIdentityBaselineStore.Identity> currentMap =
                current == null ? Collections.emptyMap() : current.byPackage;
        Set<String> presentNow = new HashSet<>(currentMap.keySet());
        List<ScanFinding> findings = new ArrayList<>();

        for (State old : new ArrayList<>(next.values())) {
            if (old == null || old.packageName.isEmpty()) continue;
            if (!presentNow.contains(old.packageName)) {
                next.put(old.packageName, new State(
                        old.packageName,
                        true,
                        old.versionCode,
                        old.installer,
                        old.currentSigners));
            }
        }

        List<String> packages = new ArrayList<>(currentMap.keySet());
        packages.sort(String.CASE_INSENSITIVE_ORDER);
        for (String packageName : packages) {
            PackageIdentityBaselineStore.Identity now = currentMap.get(packageName);
            if (now == null) continue;
            State old = next.get(packageName);

            if (old == null) {
                next.put(packageName, fromIdentity(now, false));
                continue;
            }

            if (old.missingAfterSeen) {
                findings.add(reappearanceFinding(old, now));
            }
            next.put(packageName, fromIdentity(now, false));
        }

        return new UpdateResult(trim(new Snapshot(next)), findings);
    }

    static ScanFinding reappearanceFinding(
            State before,
            PackageIdentityBaselineStore.Identity now) {
        boolean signerChanged = before != null
                && !before.currentSigners.isEmpty()
                && !now.currentSigners.isEmpty()
                && !before.currentSigners.equals(now.currentSigners);
        boolean signerContinuity = signerChanged
                && now.signingLineage.containsAll(before.currentSigners);
        boolean downgraded = before != null
                && before.versionCode > 0
                && now.versionCode > 0
                && now.versionCode < before.versionCode;
        boolean installerChanged = before != null
                && !before.installer.isEmpty()
                && !now.installer.isEmpty()
                && !before.installer.equals(now.installer);

        ScanFinding.Level level = ScanFinding.Level.LOW;
        int points = 1;
        if (signerChanged && !signerContinuity) {
            level = ScanFinding.Level.HIGH;
            points = 7;
        } else if (downgraded || installerChanged) {
            level = ScanFinding.Level.MEDIUM;
            points = 4;
        }

        StringBuilder detail = new StringBuilder(
                "O pacote estava presente em uma linha de base anterior, ficou ausente em uma "
                        + "verificação completa e voltou a aparecer.");
        if (signerChanged && signerContinuity) {
            detail.append(" A assinatura mudou com continuidade pela linhagem de certificados.");
        } else if (signerChanged) {
            detail.append(" A assinatura atual não mantém continuidade observável com a assinatura anterior.");
        }
        if (downgraded) {
            detail.append(" O versionCode reapareceu menor que o valor observado antes da ausência.");
        }
        if (installerChanged) {
            detail.append(" A origem de instalação também mudou.");
        }
        detail.append(" Reaparecimento não prova persistência maliciosa: reinstalação, restauração "
                + "de backup ou atualização do sistema podem explicar a mudança.");

        ScanFinding finding = new ScanFinding(
                level,
                "Aplicativo reapareceu após ficar ausente",
                detail.toString(),
                now.packageName,
                points,
                "Confirme se você reinstalou ou restaurou este aplicativo e reconhece sua origem atual")
                .withEvidence(
                        ScanFinding.EvidenceSource.DERIVED,
                        ScanFinding.EvidenceTag.CORRELATION)
                .withAttribute(ATTR_CHANGE_REAPPEARED, "1");

        if (signerChanged && !signerContinuity) {
            finding = finding
                    .withTags(ScanFinding.EvidenceTag.INSTALL_TRUST)
                    .withAttribute(ATTR_REAPPEAR_SIGNER_MISMATCH, "1");
        } else if (signerChanged) {
            finding = finding.withAttribute(ATTR_REAPPEAR_SIGNER_ROTATION, "1");
        }
        if (downgraded) {
            finding = finding
                    .withTags(ScanFinding.EvidenceTag.INSTALL_TRUST)
                    .withAttribute(ATTR_REAPPEAR_DOWNGRADE, "1");
        }
        if (installerChanged) {
            finding = finding
                    .withTags(ScanFinding.EvidenceTag.INSTALL_TRUST)
                    .withAttribute(ATTR_REAPPEAR_INSTALLER_CHANGED, "1");
        }
        return finding;
    }

    static String encode(Snapshot snapshot) {
        if (snapshot == null || snapshot.states.isEmpty()) return "";
        List<String> packages = new ArrayList<>(snapshot.states.keySet());
        packages.sort(String.CASE_INSENSITIVE_ORDER);

        StringBuilder out = new StringBuilder();
        int written = 0;
        for (String packageName : packages) {
            if (written >= MAX_TRACKED_PACKAGES) break;
            State state = snapshot.states.get(packageName);
            if (state == null) continue;
            if (out.length() > 0) out.append('\n');
            out.append(encodePart(state.packageName)).append('\t')
                    .append(state.missingAfterSeen ? "1" : "0").append('\t')
                    .append(state.versionCode).append('\t')
                    .append(encodePart(state.installer)).append('\t')
                    .append(encodePart(join(state.currentSigners)));
            written++;
        }
        return out.toString();
    }

    static Snapshot decode(String encoded) {
        Map<String, State> states = new HashMap<>();
        if (encoded == null || encoded.trim().isEmpty()) return new Snapshot(states);

        for (String line : encoded.split("\n")) {
            if (states.size() >= MAX_TRACKED_PACKAGES) break;
            String[] fields = line.split("\t", -1);
            if (fields.length != 5) continue;
            try {
                String packageName = decodePart(fields[0]);
                if (packageName.trim().isEmpty()) continue;
                boolean missing = "1".equals(fields[1]);
                long version = Long.parseLong(fields[2]);
                String installer = decodePart(fields[3]);
                Set<String> signers = parseSet(decodePart(fields[4]));
                states.put(
                        packageName,
                        new State(packageName, missing, version, installer, signers));
            } catch (RuntimeException ignored) {
                // Keep the valid portion of the state.
            }
        }
        return new Snapshot(states);
    }

    private static Snapshot trim(Snapshot snapshot) {
        if (snapshot == null || snapshot.states.size() <= MAX_TRACKED_PACKAGES) {
            return snapshot == null ? Snapshot.empty() : snapshot;
        }
        List<String> packages = new ArrayList<>(snapshot.states.keySet());
        packages.sort(String.CASE_INSENSITIVE_ORDER);
        Map<String, State> trimmed = new HashMap<>();
        for (String pkg : packages) {
            if (trimmed.size() >= MAX_TRACKED_PACKAGES) break;
            trimmed.put(pkg, snapshot.states.get(pkg));
        }
        return new Snapshot(trimmed);
    }

    private static State fromIdentity(
            PackageIdentityBaselineStore.Identity identity,
            boolean missing) {
        return new State(
                identity.packageName,
                missing,
                identity.versionCode,
                identity.installer,
                identity.currentSigners);
    }

    private static Set<String> normalized(Set<String> values) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (values != null) {
            for (String value : values) {
                if (value == null) continue;
                String clean = value.trim().toUpperCase(Locale.ROOT);
                if (!clean.isEmpty()) out.add(clean);
            }
        }
        return Collections.unmodifiableSet(out);
    }

    private static Set<String> parseSet(String value) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (value == null || value.trim().isEmpty()) return out;
        for (String item : value.split(",")) {
            String clean = item.trim().toUpperCase(Locale.ROOT);
            if (!clean.isEmpty()) out.add(clean);
        }
        return out;
    }

    private static String join(Set<String> values) {
        if (values == null || values.isEmpty()) return "";
        List<String> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        return String.join(",", sorted);
    }

    private static String encodePart(String value) {
        String safe = value == null ? "" : value;
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(safe.getBytes(StandardCharsets.UTF_8));
    }

    private static String decodePart(String value) {
        if (value == null || value.isEmpty()) return "";
        return new String(
                Base64.getUrlDecoder().decode(value),
                StandardCharsets.UTF_8);
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
