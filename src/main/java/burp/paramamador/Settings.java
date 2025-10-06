package burp.paramamador;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Runtime settings for Paramamador with safe defaults.
 */
public class Settings {
    private volatile boolean scopeOnly = false;
    private volatile int autoSaveSeconds = 300;
    private volatile int maxInlineJsKb = 200;
    private volatile int maxQueueSize = 200;
    private volatile int workerThreads = Math.max(2, Runtime.getRuntime().availableProcessors() / 2);
    private final List<String> ignoredPatterns = Collections.synchronizedList(new ArrayList<>(List.of(
            "jquery", "bootstrap", "google-analytics", "gtag.js", "gpt.js", "segment"
    )));
    // Global values to ignore as endpoints (exact value match), e.g., mime types like "text/plain"
    private final List<String> globalIgnoredValues = Collections.synchronizedList(new ArrayList<>(List.of(
            "text/plain"
    )));

    private volatile Path exportDir = Paths.get(System.getProperty("user.home"), ".paramamador");
    private volatile boolean overwriteOnSave = true;
    private volatile String snapshotNamePrefix = null; // optional user-provided base name for JSON filenames

    public boolean isScopeOnly() { return scopeOnly; }
    public void setScopeOnly(boolean scopeOnly) { this.scopeOnly = scopeOnly; }

    public int getAutoSaveSeconds() { return autoSaveSeconds; }
    public void setAutoSaveSeconds(int autoSaveSeconds) { this.autoSaveSeconds = Math.max(30, autoSaveSeconds); }

    public int getMaxInlineJsKb() { return maxInlineJsKb; }
    public void setMaxInlineJsKb(int maxInlineJsKb) { this.maxInlineJsKb = Math.max(10, maxInlineJsKb); }

    public int getMaxQueueSize() { return maxQueueSize; }
    public void setMaxQueueSize(int maxQueueSize) { this.maxQueueSize = Math.max(50, maxQueueSize); }

    public int getWorkerThreads() { return workerThreads; }
    public void setWorkerThreads(int workerThreads) { this.workerThreads = Math.max(1, workerThreads); }

    public List<String> getIgnoredPatterns() { return new ArrayList<>(ignoredPatterns); }
    public void addIgnoredPattern(String p) { if (p != null && !p.isBlank()) ignoredPatterns.add(p); }
    public void removeIgnoredPattern(String p) { ignoredPatterns.remove(p); }

    public List<String> getGlobalIgnoredValues() { return new ArrayList<>(globalIgnoredValues); }
    public void addGlobalIgnoredValue(String v) { if (v != null && !v.isBlank()) globalIgnoredValues.add(v); }
    public void removeGlobalIgnoredValue(String v) { globalIgnoredValues.remove(v); }

    public Path getExportDir() { return exportDir; }
    public void setExportDir(Path exportDir) { if (exportDir != null) this.exportDir = exportDir; }

    public boolean isOverwriteOnSave() { return overwriteOnSave; }
    public void setOverwriteOnSave(boolean overwriteOnSave) { this.overwriteOnSave = overwriteOnSave; }

    public String getSnapshotNamePrefix() { return snapshotNamePrefix; }
    public void setSnapshotNamePrefix(String prefix) { this.snapshotNamePrefix = (prefix == null || prefix.isBlank()) ? null : prefix; }

    // Ignored JS source patterns persistence (substring match against JS URL)
    public Path ignoredFilePath() { return exportDir.resolve("paramamador_ignored.txt"); }
    public synchronized void loadIgnoredFromExportDir() {
        try {
            Path file = ignoredFilePath();
            Files.createDirectories(file.getParent());
            if (Files.exists(file)) {
                List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
                List<String> cleaned = new ArrayList<>();
                if (lines != null) {
                    for (String s : lines) {
                        if (s == null) continue;
                        String t = s.trim();
                        if (!t.isEmpty()) cleaned.add(t);
                    }
                }
                synchronized (ignoredPatterns) {
                    ignoredPatterns.clear();
                    ignoredPatterns.addAll(cleaned);
                }
            } else {
                saveIgnoredToExportDir();
            }
        } catch (Throwable ignored) {}
    }
    public synchronized void saveIgnoredToExportDir() {
        try {
            Path file = ignoredFilePath();
            Files.createDirectories(file.getParent());
            List<String> vals;
            synchronized (ignoredPatterns) { vals = new ArrayList<>(ignoredPatterns); }
            Files.write(file, vals, StandardCharsets.UTF_8);
        } catch (Throwable ignored) {}
    }

    // Global ignored endpoint values persistence (exact match against endpoint string)
    public Path globalIgnoredFilePath() { return exportDir.resolve("paramamador_global_ignored.txt"); }
    public synchronized void loadGlobalIgnoredFromExportDir() {
        try {
            Path file = globalIgnoredFilePath();
            Files.createDirectories(file.getParent());
            if (Files.exists(file)) {
                List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
                List<String> cleaned = new ArrayList<>();
                if (lines != null) {
                    for (String s : lines) {
                        if (s == null) continue;
                        String t = s.trim();
                        if (!t.isEmpty()) cleaned.add(t);
                    }
                }
                synchronized (globalIgnoredValues) {
                    globalIgnoredValues.clear();
                    globalIgnoredValues.addAll(cleaned);
                }
            } else {
                saveGlobalIgnoredToExportDir();
            }
        } catch (Throwable ignored) {}
    }
    public synchronized void saveGlobalIgnoredToExportDir() {
        try {
            Path file = globalIgnoredFilePath();
            Files.createDirectories(file.getParent());
            List<String> vals;
            synchronized (globalIgnoredValues) { vals = new ArrayList<>(globalIgnoredValues); }
            Files.write(file, vals, StandardCharsets.UTF_8);
        } catch (Throwable ignored) {}
    }
}
