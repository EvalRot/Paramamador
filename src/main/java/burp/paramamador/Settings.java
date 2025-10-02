package burp.paramamador;

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

    private volatile Path exportDir = Paths.get(System.getProperty("user.home"), ".paramamador");
    private volatile boolean overwriteOnSave = true;

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

    public Path getExportDir() { return exportDir; }
    public void setExportDir(Path exportDir) { if (exportDir != null) this.exportDir = exportDir; }

    public boolean isOverwriteOnSave() { return overwriteOnSave; }
    public void setOverwriteOnSave(boolean overwriteOnSave) { this.overwriteOnSave = overwriteOnSave; }
}

