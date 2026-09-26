package com.darkshield.security;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class SecurityBaselineStore {
    private static final String PREFS = "darkshield_security_baseline";
    private static final String KEY_SCHEMA = "schema";
    private static final String KEY_DATA = "data";
    private static final int SCHEMA_VERSION = 1;

    private static final EnumSet<ScanFinding.EvidenceTag> TRACKED_TAGS = EnumSet.of(
            ScanFinding.EvidenceTag.ACTIVE_ACCESS,
            ScanFinding.EvidenceTag.PERSISTENCE,
            ScanFinding.EvidenceTag.REMOTE_CONTROL,
            ScanFinding.EvidenceTag.SENSITIVE_DATA,
            ScanFinding.EvidenceTag.INSTALL_TRUST);

    static final class Snapshot {
        final Map<String, EnumSet<ScanFinding.EvidenceTag>> byPackage;

        Snapshot(Map<String, EnumSet<ScanFinding.EvidenceTag>> byPackage) {
            Map<String, EnumSet<ScanFinding.EvidenceTag>> copy = new HashMap<>();
            if (byPackage != null) {
                for (Map.Entry<String, EnumSet<ScanFinding.EvidenceTag>> entry
                        : byPackage.entrySet()) {
                    if (entry.getKey() == null || entry.getValue() == null) continue;
                    copy.put(
                            entry.getKey(),
                            entry.getValue().isEmpty()
                                    ? EnumSet.noneOf(ScanFinding.EvidenceTag.class)
                                    : EnumSet.copyOf(entry.getValue()));
                }
            }
            this.byPackage = Collections.unmodifiableMap(copy);
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

    private SecurityBaselineStore() {}

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

    static Snapshot fromFindings(List<ScanFinding> findings) {
        Map<String, EnumSet<ScanFinding.EvidenceTag>> byPackage = new HashMap<>();
        if (findings == null) return new Snapshot(byPackage);

        for (ScanFinding finding : findings) {
            if (finding == null
                    || finding.packageName == null
                    || finding.packageName.trim().isEmpty()
                    || finding.evidenceSource != ScanFinding.EvidenceSource.OBSERVED
                    || finding.evidenceTags == null
                    || finding.evidenceTags.isEmpty()) {
                continue;
            }

            EnumSet<ScanFinding.EvidenceTag> observed = byPackage.get(finding.packageName);
            if (observed == null) {
                observed = EnumSet.noneOf(ScanFinding.EvidenceTag.class);
                byPackage.put(finding.packageName, observed);
            }
            for (ScanFinding.EvidenceTag tag : finding.evidenceTags) {
                if (TRACKED_TAGS.contains(tag)) observed.add(tag);
            }
        }

        byPackage.entrySet().removeIf(entry -> entry.getValue().isEmpty());
        return new Snapshot(byPackage);
    }

    static List<ScanFinding> compare(Snapshot previous, Snapshot current) {
        if (previous == null || current == null) return Collections.emptyList();

        List<String> packages = new ArrayList<>(current.byPackage.keySet());
        packages.sort((left, right) -> {
            int order = left.compareToIgnoreCase(right);
            return order != 0 ? order : left.compareTo(right);
        });

        List<ScanFinding> changes = new ArrayList<>();
        for (String packageName : packages) {
            EnumSet<ScanFinding.EvidenceTag> now = current.byPackage.get(packageName);
            if (now == null || now.isEmpty()) continue;

            EnumSet<ScanFinding.EvidenceTag> before =
                    previous.byPackage.get(packageName);
            EnumSet<ScanFinding.EvidenceTag> added = EnumSet.copyOf(now);
            if (before != null) added.removeAll(before);
            if (added.isEmpty()) continue;

            boolean active = added.contains(ScanFinding.EvidenceTag.ACTIVE_ACCESS);
            boolean sensitive = added.contains(ScanFinding.EvidenceTag.SENSITIVE_DATA);
            boolean remote = added.contains(ScanFinding.EvidenceTag.REMOTE_CONTROL);
            boolean install = added.contains(ScanFinding.EvidenceTag.INSTALL_TRUST);

            ScanFinding.Level level;
            int points;
            if (active && (sensitive || remote || install)) {
                level = ScanFinding.Level.MEDIUM;
                points = 4;
            } else if (active || remote || install) {
                level = ScanFinding.Level.MEDIUM;
                points = 3;
            } else {
                level = ScanFinding.Level.LOW;
                points = 1;
            }

            changes.add(new ScanFinding(
                    level,
                    "Novo acesso observado desde a última verificação",
                    "Novos sinais operacionais: " + joinTags(added)
                            + ". A mudança pode ser legítima após você conceder uma permissão, "
                            + "alterar configurações ou atualizar um aplicativo; confirme se era esperada.",
                    packageName,
                    points,
                    "Revise o aplicativo e os acessos concedidos se você não reconhece essa mudança")
                    .withEvidence(
                            ScanFinding.EvidenceSource.DERIVED,
                            ScanFinding.EvidenceTag.CORRELATION));
        }
        return changes;
    }

    static String encode(Snapshot snapshot) {
        if (snapshot == null || snapshot.byPackage.isEmpty()) return "";

        List<String> packages = new ArrayList<>(snapshot.byPackage.keySet());
        Collections.sort(packages);
        StringBuilder out = new StringBuilder();
        for (String packageName : packages) {
            if (packageName == null
                    || packageName.indexOf('\t') >= 0
                    || packageName.indexOf('\n') >= 0
                    || packageName.indexOf('\r') >= 0) {
                continue;
            }
            EnumSet<ScanFinding.EvidenceTag> tags = snapshot.byPackage.get(packageName);
            if (tags == null || tags.isEmpty()) continue;
            if (out.length() > 0) out.append('\n');
            out.append(packageName).append('\t').append(joinTags(tags));
        }
        return out.toString();
    }

    static Snapshot decode(String encoded) {
        Map<String, EnumSet<ScanFinding.EvidenceTag>> byPackage = new HashMap<>();
        if (encoded == null || encoded.trim().isEmpty()) return new Snapshot(byPackage);

        String[] lines = encoded.split("\\n");
        for (String line : lines) {
            if (line == null || line.isEmpty()) continue;
            int separator = line.indexOf('\t');
            if (separator <= 0 || separator >= line.length() - 1) continue;
            String packageName = line.substring(0, separator).trim();
            if (packageName.isEmpty()) continue;

            EnumSet<ScanFinding.EvidenceTag> tags =
                    EnumSet.noneOf(ScanFinding.EvidenceTag.class);
            String[] names = line.substring(separator + 1).split(",");
            for (String name : names) {
                try {
                    ScanFinding.EvidenceTag tag =
                            ScanFinding.EvidenceTag.valueOf(name.trim());
                    if (TRACKED_TAGS.contains(tag)) tags.add(tag);
                } catch (IllegalArgumentException ignored) {
                    // Forward-compatible: ignore tags unknown to this build.
                }
            }
            if (!tags.isEmpty()) byPackage.put(packageName, tags);
        }
        return new Snapshot(byPackage);
    }

    private static LoadedBaseline load(Context context) {
        SharedPreferences prefs =
                context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        if (prefs.getInt(KEY_SCHEMA, -1) != SCHEMA_VERSION
                || !prefs.contains(KEY_DATA)) {
            return new LoadedBaseline(false, Snapshot.empty());
        }
        return new LoadedBaseline(true, decode(prefs.getString(KEY_DATA, "")));
    }

    private static void save(Context context, Snapshot snapshot) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .putInt(KEY_SCHEMA, SCHEMA_VERSION)
                .putString(KEY_DATA, encode(snapshot))
                .apply();
    }

    private static String joinTags(Iterable<ScanFinding.EvidenceTag> tags) {
        StringBuilder out = new StringBuilder();
        for (ScanFinding.EvidenceTag tag : tags) {
            if (tag == null) continue;
            if (out.length() > 0) out.append(", ");
            out.append(tag.name());
        }
        return out.toString();
    }
}
