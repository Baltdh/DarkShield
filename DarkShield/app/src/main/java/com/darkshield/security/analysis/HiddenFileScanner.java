package com.darkshield.security.analysis;

import android.content.Context;
import android.os.Build;
import android.os.Environment;
import com.darkshield.security.ScanFinding;
import java.io.File;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Bounded filesystem inspection that only traverses paths the current process
 * can read. It never attempts to bypass Android sandboxing or escalate access.
 */
public final class HiddenFileScanner {
    private static final int MAX_FILES = 2500;
    private static final int MAX_DEPTH = 5;
    private static final long MAX_SINGLE_FILE_BYTES = 256L * 1024L * 1024L;

    private HiddenFileScanner() {}

    public static List<ScanFinding> scan(Context context) {
        List<ScanFinding> out = new ArrayList<>();
        if (context == null) return out;

        boolean broadStorage = hasBroadStorageAccess();
        out.add(new ScanFinding(
                ScanFinding.Level.INFO,
                "Cobertura da varredura de arquivos ocultos",
                broadStorage
                        ? "O Android permite acesso amplo ao armazenamento compartilhado; áreas privadas de outros apps e diretórios protegidos continuam fora do alcance sem privilégios adicionais."
                        : "A varredura está limitada aos caminhos legíveis pelo app. Diretórios privados de outros apps e várias áreas protegidas do sistema não podem ser lidos pelo DarkShield.",
                null, 0,
                broadStorage ? null : "Conceda acesso amplo ao armazenamento apenas se desejar ampliar a cobertura de arquivos compartilhados"));

        List<Root> roots = new ArrayList<>();
        addRoot(roots, new File("/system"), false, "system");
        addRoot(roots, new File("/vendor"), false, "vendor");
        addRoot(roots, new File("/product"), false, "product");
        addRoot(roots, new File("/odm"), false, "odm");
        addRoot(roots, new File("/data/local/tmp"), true, "data-local-tmp");

        File appFiles = context.getFilesDir();
        if (appFiles != null) addRoot(roots, appFiles, true, "app-internal");
        File appCache = context.getCacheDir();
        if (appCache != null) addRoot(roots, appCache, true, "app-cache");

        File[] external = context.getExternalFilesDirs(null);
        if (external != null) {
            for (File f : external) if (f != null) addRoot(roots, f, true, "app-external");
        }

        if (broadStorage) {
            try {
                File shared = Environment.getExternalStorageDirectory();
                if (shared != null) addRoot(roots, shared, true, "shared-storage");
            } catch (Exception ignored) {}
        }

        int[] inspected = new int[] {0};
        Set<String> seen = new HashSet<>();
        for (Root root : roots) {
            if (inspected[0] >= MAX_FILES) break;
            traverse(root, out, inspected, seen);
        }

        out.add(new ScanFinding(
                ScanFinding.Level.INFO,
                "Arquivos verificados na busca oculta",
                inspected[0] + " entrada(s) de arquivo/diretório analisada(s) em caminhos legíveis",
                null, 0, null));
        return out;
    }

    private static void traverse(
            Root root,
            List<ScanFinding> out,
            int[] inspected,
            Set<String> seen) {
        if (root.file == null || !root.file.exists() || !root.file.canRead()) return;

        ArrayDeque<Node> queue = new ArrayDeque<>();
        queue.add(new Node(root.file, 0));

        while (!queue.isEmpty() && inspected[0] < MAX_FILES) {
            Node node = queue.removeFirst();
            File f = node.file;
            String path;
            try {
                path = f.getCanonicalPath();
            } catch (Exception e) {
                path = f.getAbsolutePath();
            }
            if (!seen.add(path)) continue;
            inspected[0]++;

            if (f.isFile()) {
                inspectFile(f, root, out);
                continue;
            }
            if (!f.isDirectory() || node.depth >= MAX_DEPTH) continue;

            File[] children;
            try {
                children = f.listFiles();
            } catch (SecurityException e) {
                children = null;
            }
            if (children == null) continue;
            for (File child : children) {
                if (child == null || inspected[0] >= MAX_FILES) break;
                queue.addLast(new Node(child, node.depth + 1));
            }
        }
    }

    private static void inspectFile(File file, Root root, List<ScanFinding> out) {
        if (file.length() > MAX_SINGLE_FILE_BYTES) return;
        int score = HiddenFileHeuristics.riskScore(file, root.sharedWritable);
        if (score < 4) return;

        ScanFinding.Level level = score >= 8
                ? ScanFinding.Level.HIGH
                : score >= 6 ? ScanFinding.Level.MEDIUM : ScanFinding.Level.LOW;

        StringBuilder why = new StringBuilder();
        if (HiddenFileHeuristics.isHiddenName(file.getName())) why.append("nome oculto; ");
        if (HiddenFileHeuristics.looksLikeDisguisedPayload(file.getName())) {
            why.append("extensão dupla/disfarçada; ");
        } else if (HiddenFileHeuristics.hasExecutablePayloadExtension(file.getName())) {
            why.append("tipo executável/payload; ");
        }
        if (file.canExecute()) why.append("marcado como executável; ");
        if (root.sharedWritable) why.append("local gravável/compartilhado; ");

        out.add(new ScanFinding(
                level,
                "Arquivo oculto ou payload suspeito",
                file.getAbsolutePath() + " — " + why.toString(),
                null,
                score,
                "Não exclua automaticamente: confirme origem, hash e relação com algum aplicativo antes de remover"));
    }

    private static boolean hasBroadStorageAccess() {
        if (Build.VERSION.SDK_INT < 30) {
            return Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED)
                    || Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED_READ_ONLY);
        }
        try {
            return Environment.isExternalStorageManager();
        } catch (Exception e) {
            return false;
        }
    }

    private static void addRoot(List<Root> roots, File file, boolean writable, String label) {
        if (file != null) roots.add(new Root(file, writable, label));
    }

    private static final class Root {
        final File file;
        final boolean sharedWritable;
        final String label;

        Root(File file, boolean sharedWritable, String label) {
            this.file = file;
            this.sharedWritable = sharedWritable;
            this.label = label;
        }
    }

    private static final class Node {
        final File file;
        final int depth;

        Node(File file, int depth) {
            this.file = file;
            this.depth = depth;
        }
    }
}
