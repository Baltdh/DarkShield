package com.darkshield.security;

import android.content.Context;
import android.content.SharedPreferences;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;

public final class PackageIdentityBaselineStore {
    public static final String ATTR_VERSION_CODE = "identity.version_code";
    public static final String ATTR_INSTALLER = "identity.installer";
    public static final String ATTR_FIRST_INSTALL = "identity.first_install";
    public static final String ATTR_LAST_UPDATE = "identity.last_update";
    public static final String ATTR_CURRENT_SIGNERS = "identity.current_signers";
    public static final String ATTR_SIGNING_LINEAGE = "identity.signing_lineage";
    public static final String ATTR_CHANGE_SIGNER_MISMATCH = "identity.change_signer_mismatch";
    public static final String ATTR_CHANGE_SIGNER_ROTATION = "identity.change_signer_rotation";
    public static final String ATTR_CHANGE_DOWNGRADE = "identity.change_downgrade";
    public static final String ATTR_CHANGE_INSTALLER = "identity.change_installer";
    public static final String ATTR_CHANGE_REINSTALL = "identity.change_reinstall";

    private static final String PREFS = "darkshield_package_identity_baseline";
    private static final String KEY_SCHEMA = "schema";
    private static final String KEY_DATA = "data";
    private static final int SCHEMA_VERSION = 1;

    static final class Identity {
        final String packageName;
        final long versionCode;
        final String installer;
        final long firstInstallTime;
        final long lastUpdateTime;
        final Set<String> currentSigners;
        final Set<String> signingLineage;

        Identity(
                String packageName,
                long versionCode,
                String installer,
                long firstInstallTime,
                long lastUpdateTime,
                Set<String> currentSigners,
                Set<String> signingLineage) {
            this.packageName = packageName == null ? "" : packageName.trim();
            this.versionCode = Math.max(0L, versionCode);
            this.installer = installer == null ? "" : installer.trim();
            this.firstInstallTime = Math.max(0L, firstInstallTime);
            this.lastUpdateTime = Math.max(0L, lastUpdateTime);
            this.currentSigners = immutableNormalized(currentSigners);
            this.signingLineage = immutableNormalized(signingLineage);
        }
    }

    static final class Snapshot {
        final Map<String, Identity> byPackage;

        Snapshot(Map<String, Identity> byPackage) {
            Map<String, Identity> copy = new HashMap<>();
            if (byPackage != null) {
                for (Map.Entry<String, Identity> entry : byPackage.entrySet()) {
                    if (entry == null
                            || entry.getKey() == null
                            || entry.getValue() == null
                            || entry.getKey().trim().isEmpty()) {
                        continue;
                    }
                    copy.put(entry.getKey(), entry.getValue());
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

    private PackageIdentityBaselineStore() {}

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
        Map<String, Identity> identities = new HashMap<>();
        if (findings == null) return new Snapshot(identities);

        for (ScanFinding finding : findings) {
            if (finding == null
                    || finding.packageName == null
                    || finding.packageName.trim().isEmpty()
                    || finding.attributes == null
                    || !finding.attributes.containsKey(ATTR_VERSION_CODE)) {
                continue;
            }

            Identity identity = identityFromFinding(finding);
            if (identity != null) identities.put(identity.packageName, identity);
        }
        return new Snapshot(identities);
    }

    static List<ScanFinding> compare(Snapshot previous, Snapshot current) {
        if (previous == null || current == null) return Collections.emptyList();

        List<String> packages = new ArrayList<>(current.byPackage.keySet());
        packages.sort(String.CASE_INSENSITIVE_ORDER);

        List<ScanFinding> findings = new ArrayList<>();
        for (String packageName : packages) {
            Identity before = previous.byPackage.get(packageName);
            Identity now = current.byPackage.get(packageName);
            if (before == null || now == null) continue;

            boolean signerChanged = !before.currentSigners.equals(now.currentSigners)
                    && !before.currentSigners.isEmpty()
                    && !now.currentSigners.isEmpty();
            boolean signerContinuity = signerChanged
                    && hasSigningContinuity(before.currentSigners, now.signingLineage);
            boolean installerChanged = !before.installer.equals(now.installer)
                    && !before.installer.isEmpty()
                    && !now.installer.isEmpty();
            boolean downgraded = before.versionCode > 0
                    && now.versionCode > 0
                    && now.versionCode < before.versionCode;
            boolean reinstalled = before.firstInstallTime > 0
                    && now.firstInstallTime > 0
                    && before.firstInstallTime != now.firstInstallTime;

            if (!signerChanged && !installerChanged && !downgraded && !reinstalled) {
                continue;
            }

            StringBuilder detail = new StringBuilder();
            ScanFinding.Level level = ScanFinding.Level.INFO;
            int points = 0;

            if (signerChanged) {
                if (signerContinuity) {
                    append(detail,
                            "O certificado atual mudou, mas a linhagem atual inclui o certificado anterior; "
                                    + "isso é compatível com rotação legítima de chave no Android");
                } else {
                    append(detail,
                            "O certificado atual mudou e a linhagem observada não contém o certificado anterior");
                    level = ScanFinding.Level.HIGH;
                    points = Math.max(points, 7);
                }
            }

            if (downgraded) {
                append(detail,
                        "VersionCode reduziu de " + before.versionCode + " para " + now.versionCode);
                if (level.ordinal() < ScanFinding.Level.MEDIUM.ordinal()) {
                    level = ScanFinding.Level.MEDIUM;
                }
                points = Math.max(points, 4);
            }

            if (installerChanged) {
                append(detail,
                        "Instalador mudou de " + before.installer + " para " + now.installer);
                if (level.ordinal() < ScanFinding.Level.LOW.ordinal()) {
                    level = ScanFinding.Level.LOW;
                }
                points = Math.max(points, 1);
            }

            if (reinstalled) {
                append(detail,
                        "O horário de primeira instalação mudou, compatível com remoção/reinstalação do pacote");
                if (level.ordinal() < ScanFinding.Level.LOW.ordinal()) {
                    level = ScanFinding.Level.LOW;
                }
                points = Math.max(points, 1);
            }

            String action = signerChanged && !signerContinuity
                    ? "Confirme se você reinstalou o aplicativo de outra fonte; compare com a versão oficial antes de confiar nele"
                    : downgraded
                            ? "Confirme se o downgrade foi intencional e obtenha a versão atualizada da fonte oficial"
                            : "Confirme se a mudança de origem/reinstalação foi intencional";

            ScanFinding identityFinding = new ScanFinding(
                    level,
                    signerChanged && !signerContinuity
                            ? "Identidade de assinatura do aplicativo mudou"
                            : signerChanged
                                    ? "Rotação de assinatura observada"
                                    : "Identidade de instalação do aplicativo mudou",
                    detail.toString(),
                    packageName,
                    points,
                    action);

            boolean securityRelevantChange =
                    (signerChanged && !signerContinuity)
                            || installerChanged
                            || downgraded
                            || reinstalled;
            identityFinding = securityRelevantChange
                    ? identityFinding.withEvidence(
                            ScanFinding.EvidenceSource.DERIVED,
                            ScanFinding.EvidenceTag.INSTALL_TRUST,
                            ScanFinding.EvidenceTag.CORRELATION)
                    : identityFinding.withEvidence(ScanFinding.EvidenceSource.DERIVED);

            if (signerChanged && !signerContinuity) {
                identityFinding = identityFinding.withAttribute(
                        ATTR_CHANGE_SIGNER_MISMATCH, "1");
            } else if (signerChanged) {
                identityFinding = identityFinding.withAttribute(
                        ATTR_CHANGE_SIGNER_ROTATION, "1");
            }
            if (downgraded) {
                identityFinding = identityFinding.withAttribute(
                        ATTR_CHANGE_DOWNGRADE, "1");
            }
            if (installerChanged) {
                identityFinding = identityFinding.withAttribute(
                        ATTR_CHANGE_INSTALLER, "1");
            }
            if (reinstalled) {
                identityFinding = identityFinding.withAttribute(
                        ATTR_CHANGE_REINSTALL, "1");
            }
            findings.add(identityFinding);
        }
        return findings;
    }

    static boolean hasSigningContinuity(
            Set<String> previousCurrentSigners,
            Set<String> currentLineage) {
        if (previousCurrentSigners == null
                || previousCurrentSigners.isEmpty()
                || currentLineage == null
                || currentLineage.isEmpty()) {
            return false;
        }
        return currentLineage.containsAll(previousCurrentSigners);
    }

    static String encode(Snapshot snapshot) {
        if (snapshot == null || snapshot.byPackage.isEmpty()) return "";

        List<String> packages = new ArrayList<>(snapshot.byPackage.keySet());
        packages.sort(String.CASE_INSENSITIVE_ORDER);

        StringBuilder out = new StringBuilder();
        for (String packageName : packages) {
            Identity identity = snapshot.byPackage.get(packageName);
            if (identity == null) continue;
            if (out.length() > 0) out.append('\n');
            out.append(encodePart(identity.packageName)).append('\t')
                    .append(identity.versionCode).append('\t')
                    .append(encodePart(identity.installer)).append('\t')
                    .append(identity.firstInstallTime).append('\t')
                    .append(identity.lastUpdateTime).append('\t')
                    .append(encodePart(join(identity.currentSigners))).append('\t')
                    .append(encodePart(join(identity.signingLineage)));
        }
        return out.toString();
    }

    static Snapshot decode(String encoded) {
        Map<String, Identity> identities = new HashMap<>();
        if (encoded == null || encoded.trim().isEmpty()) {
            return new Snapshot(identities);
        }

        for (String line : encoded.split("\\n")) {
            if (line == null || line.trim().isEmpty()) continue;
            String[] fields = line.split("\\t", -1);
            if (fields.length != 7) continue;
            try {
                String packageName = decodePart(fields[0]);
                long versionCode = Long.parseLong(fields[1]);
                String installer = decodePart(fields[2]);
                long firstInstall = Long.parseLong(fields[3]);
                long lastUpdate = Long.parseLong(fields[4]);
                Set<String> current = parseSet(decodePart(fields[5]));
                Set<String> lineage = parseSet(decodePart(fields[6]));
                if (!packageName.trim().isEmpty()) {
                    identities.put(
                            packageName,
                            new Identity(
                                    packageName,
                                    versionCode,
                                    installer,
                                    firstInstall,
                                    lastUpdate,
                                    current,
                                    lineage));
                }
            } catch (RuntimeException ignored) {
                // Ignore corrupt rows and preserve the rest of the baseline.
            }
        }
        return new Snapshot(identities);
    }

    private static Identity identityFromFinding(ScanFinding finding) {
        try {
            return new Identity(
                    finding.packageName,
                    Long.parseLong(value(finding, ATTR_VERSION_CODE, "0")),
                    value(finding, ATTR_INSTALLER, ""),
                    Long.parseLong(value(finding, ATTR_FIRST_INSTALL, "0")),
                    Long.parseLong(value(finding, ATTR_LAST_UPDATE, "0")),
                    parseSet(value(finding, ATTR_CURRENT_SIGNERS, "")),
                    parseSet(value(finding, ATTR_SIGNING_LINEAGE, "")));
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String value(ScanFinding finding, String key, String fallback) {
        String value = finding.attribute(key);
        return value == null ? fallback : value;
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

    private static Set<String> immutableNormalized(Set<String> values) {
        LinkedHashSet<String> normalized = new LinkedHashSet<>();
        if (values != null) {
            for (String value : values) {
                if (value == null) continue;
                String clean = value.trim().toUpperCase(Locale.ROOT);
                if (!clean.isEmpty()) normalized.add(clean);
            }
        }
        return Collections.unmodifiableSet(normalized);
    }

    private static Set<String> parseSet(String value) {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        if (value == null || value.trim().isEmpty()) return result;
        for (String item : value.split(",")) {
            String clean = item.trim().toUpperCase(Locale.ROOT);
            if (!clean.isEmpty()) result.add(clean);
        }
        return result;
    }

    private static String join(Set<String> values) {
        if (values == null || values.isEmpty()) return "";
        List<String> ordered = new ArrayList<>(values);
        Collections.sort(ordered);
        return String.join(",", ordered);
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

    private static void append(StringBuilder out, String value) {
        if (out.length() > 0) out.append(". ");
        out.append(value);
    }
}
