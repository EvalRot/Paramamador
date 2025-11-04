package burp.paramamador;

//
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.nio.charset.StandardCharsets;

// YAML
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.DumperOptions;

/**
 * Runtime settings for Paramamador with safe defaults.
 */
public class Settings {
    private volatile boolean scopeOnly = true;
    private volatile int autoSaveSeconds = 300;
    private volatile int maxInlineJsKb = 200;
    private volatile int maxQueueSize = 200;
    private volatile int workerThreads = Math.max(2, Runtime.getRuntime().availableProcessors() / 2);
    private final List<String> globalIgnoredSources = Collections.synchronizedList(new ArrayList<>(List.of(
            "jquery", "bootstrap", "google-analytics", "gtag.js", "gpt.js"
    )));
    // Global values to ignore as endpoints (exact value match), e.g., mime types like "text/plain"
    private final List<String> globalIgnoredValues = Collections.synchronizedList(new ArrayList<>(List.of(
            "text/plain"
    )));

    // Project-specific export dir (snapshots, project data)
    private volatile Path exportDir = defaultExportDir();
    // Global export dir for ignore lists shared across projects
    private volatile Path globalExportDir = Paths.get(System.getProperty("user.home"), ".paramamador");
    private volatile boolean overwriteOnSave = true;
    private volatile String snapshotNamePrefix = null; // optional user-provided base name for JSON filenames
    // Last project name to prefill on subsequent loads (persisted in YAML); no default
    private volatile String lastProjectName = null;
    private volatile boolean loadPreviousOnStartup = false; // whether to load prior JSON results on startup
    // Current session snapshot file targets (timestamp-based)
    private volatile Path currentParametersFile = null;
    private volatile Path currentEndpointsFile = null;

    // jsluice integration settings
    private volatile boolean enableJsluice = false;
    private volatile Path goBinDir = null; // optional, if null use env variables
    private volatile int jsluiceTimeoutSec = 30;
    private volatile int jsluiceWorkers = Math.max(2, Math.min(4, Runtime.getRuntime().availableProcessors()));
    private volatile int maxJsluiceFileMb = 8; // skip very big files
    private volatile String jsluiceStoreSubdir = "jsluice_js"; // subdir under exportDir for JS bodies

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

    public List<String> getGlobalIgnoredSources() { return new ArrayList<>(globalIgnoredSources); }
    public void addGlobalIgnoredSource(String p) { if (p != null && !p.isBlank()) globalIgnoredSources.add(p); }
    public void removeGlobalIgnoredSource(String p) { globalIgnoredSources.remove(p); }

    public List<String> getGlobalIgnoredValues() { return new ArrayList<>(globalIgnoredValues); }
    public void addGlobalIgnoredValue(String v) { if (v != null && !v.isBlank()) globalIgnoredValues.add(v); }
    public void removeGlobalIgnoredValue(String v) { globalIgnoredValues.remove(v); }

    public Path getExportDir() { return exportDir; }
    public void setExportDir(Path exportDir) { if (exportDir != null) this.exportDir = exportDir; }

    public Path getGlobalExportDir() { return globalExportDir; }
    public void setGlobalExportDir(Path dir) { if (dir != null) this.globalExportDir = dir; }

    public boolean isOverwriteOnSave() { return overwriteOnSave; }
    public void setOverwriteOnSave(boolean overwriteOnSave) { this.overwriteOnSave = overwriteOnSave; }

    public String getSnapshotNamePrefix() { return snapshotNamePrefix; }
    public void setSnapshotNamePrefix(String prefix) { this.snapshotNamePrefix = (prefix == null || prefix.isBlank()) ? null : prefix; }
    public String getLastProjectName() { return lastProjectName; }
    public void setLastProjectName(String v) { this.lastProjectName = (v == null || v.isBlank()) ? null : v; }

    public Path getCurrentParametersFile() { return currentParametersFile; }
    public void setCurrentParametersFile(Path p) { this.currentParametersFile = p; }
    public Path getCurrentEndpointsFile() { return currentEndpointsFile; }
    public void setCurrentEndpointsFile(Path p) { this.currentEndpointsFile = p; }

    // Per-project file that stores lines of "<full JS URL>\t<SHA-256 hash>"
    public Path scannedJsFilePath() { return exportDir.resolve("paramamador_scanned_js.txt"); }
    public Path jsluiceScannedFilePath() { return exportDir.resolve("paramamador_jsluice_scanned.txt"); }
    public Path jsluiceStoreDir() { return exportDir.resolve(jsluiceStoreSubdir); }
    public Path jsluiceResultsDir() { return exportDir.resolve("jsluice").resolve("results"); }

    // Default values for path variables like :client, :companyCode
    private final Map<String,String> variableDefaults = Collections.synchronizedMap(new LinkedHashMap<>());
    public Map<String,String> getVariableDefaults() {
        synchronized (variableDefaults) { return new LinkedHashMap<>(variableDefaults); }
    }
    public void addVariableDefault(String name, String value) {
        if (name == null || name.isBlank()) return;
        String n = name.startsWith(":") ? name.substring(1) : name;
        synchronized (variableDefaults) { variableDefaults.put(n.trim(), value == null ? "" : value.trim()); }
    }
    public void removeVariableDefault(String name) {
        if (name == null || name.isBlank()) return;
        String n = name.startsWith(":") ? name.substring(1) : name;
        synchronized (variableDefaults) { variableDefaults.remove(n.trim()); }
    }
    public Path variableDefaultsFilePath() { return exportDir.resolve("paramamador_variable_defaults.tsv"); }
    public synchronized void loadVariableDefaultsFromFile() {
        try {
            Path file = variableDefaultsFilePath();
            java.nio.file.Files.createDirectories(file.getParent());
            if (!java.nio.file.Files.isRegularFile(file)) {
                saveVariableDefaultsToFile();
                return;
            }
            java.util.List<String> lines = java.nio.file.Files.readAllLines(file, java.nio.charset.StandardCharsets.UTF_8);
            LinkedHashMap<String,String> map = new LinkedHashMap<>();
            if (lines != null) {
                for (String line : lines) {
                    if (line == null) continue;
                    String t = line.trim();
                    if (t.isEmpty()) continue;
                    int tab = t.indexOf('\t');
                    if (tab <= 0) continue;
                    String key = t.substring(0, tab).trim();
                    String val = t.substring(tab + 1).trim();
                    if (!key.isEmpty()) map.put(key, val);
                }
            }
            synchronized (variableDefaults) {
                variableDefaults.clear();
                variableDefaults.putAll(map);
            }
        } catch (Throwable ignored) {}
    }
    public synchronized void saveVariableDefaultsToFile() {
        try {
            Path file = variableDefaultsFilePath();
            java.nio.file.Files.createDirectories(file.getParent());
            java.util.List<String> out = new java.util.ArrayList<>();
            synchronized (variableDefaults) {
                for (Map.Entry<String,String> e : variableDefaults.entrySet()) {
                    out.add(e.getKey() + "\t" + (e.getValue() == null ? "" : e.getValue()));
                }
            }
            java.nio.file.Files.write(file, out, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Throwable ignored) {}
    }

    // Default request headers to include in Send-to-Repeater (per project)
    private final Map<String,String> defaultRequestHeaders = Collections.synchronizedMap(new LinkedHashMap<>());
    public Map<String,String> getDefaultHeaders() {
        synchronized (defaultRequestHeaders) { return new LinkedHashMap<>(defaultRequestHeaders); }
    }
    public void addDefaultHeader(String name, String value) {
        if (name == null || name.isBlank()) return;
        synchronized (defaultRequestHeaders) { defaultRequestHeaders.put(name.trim(), value == null ? "" : value.trim()); }
    }
    public void removeDefaultHeader(String name) {
        if (name == null || name.isBlank()) return;
        synchronized (defaultRequestHeaders) { defaultRequestHeaders.remove(name.trim()); }
    }
    public Path defaultHeadersFilePath() { return exportDir.resolve("paramamador_default_headers.tsv"); }
    public synchronized void loadDefaultHeadersFromFile() {
        try {
            Path file = defaultHeadersFilePath();
            java.nio.file.Files.createDirectories(file.getParent());
            if (!java.nio.file.Files.isRegularFile(file)) {
                saveDefaultHeadersToFile();
                return;
            }
            java.util.List<String> lines = java.nio.file.Files.readAllLines(file, java.nio.charset.StandardCharsets.UTF_8);
            LinkedHashMap<String,String> map = new LinkedHashMap<>();
            if (lines != null) {
                for (String line : lines) {
                    if (line == null) continue;
                    String t = line.trim();
                    if (t.isEmpty()) continue;
                    int tab = t.indexOf('\t');
                    if (tab <= 0) continue;
                    String key = t.substring(0, tab).trim();
                    String val = t.substring(tab + 1).trim();
                    if (!key.isEmpty()) map.put(key, val);
                }
            }
            synchronized (defaultRequestHeaders) {
                defaultRequestHeaders.clear();
                defaultRequestHeaders.putAll(map);
            }
        } catch (Throwable ignored) {}
    }
    public synchronized void saveDefaultHeadersToFile() {
        try {
            Path file = defaultHeadersFilePath();
            java.nio.file.Files.createDirectories(file.getParent());
            java.util.List<String> out = new java.util.ArrayList<>();
            synchronized (defaultRequestHeaders) {
                for (Map.Entry<String,String> e : defaultRequestHeaders.entrySet()) {
                    out.add(e.getKey() + "\t" + (e.getValue() == null ? "" : e.getValue()));
                }
            }
            java.nio.file.Files.write(file, out, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Throwable ignored) {}
    }

    public boolean isLoadPreviousOnStartup() { return loadPreviousOnStartup; }
    public void setLoadPreviousOnStartup(boolean v) { this.loadPreviousOnStartup = v; }

    public boolean isEnableJsluice() { return enableJsluice; }
    public void setEnableJsluice(boolean v) { this.enableJsluice = v; }
    public Path getGoBinDir() { return goBinDir; }
    public void setGoBinDir(Path p) { this.goBinDir = p; }
    public int getJsluiceTimeoutSec() { return jsluiceTimeoutSec; }
    public void setJsluiceTimeoutSec(int sec) { this.jsluiceTimeoutSec = Math.max(5, sec); }
    public int getJsluiceWorkers() { return jsluiceWorkers; }
    public void setJsluiceWorkers(int n) { this.jsluiceWorkers = Math.max(1, n); }
    public int getMaxJsluiceFileMb() { return maxJsluiceFileMb; }
    public void setMaxJsluiceFileMb(int mb) { this.maxJsluiceFileMb = Math.max(1, mb); }
    public String getJsluiceStoreSubdir() { return jsluiceStoreSubdir; }
    public void setJsluiceStoreSubdir(String v) { if (v != null && !v.isBlank()) this.jsluiceStoreSubdir = v; }

    private static Path defaultExportDir() {
        String home = System.getProperty("user.home");
        String date = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy MM dd"));
        return Paths.get(home, ".paramamador", date);
    }

    // YAML config persistence (stored under globalExportDir)
    public Path yamlConfigFilePath() { return globalExportDir.resolve("paramamador_settings.yaml"); }

    @SuppressWarnings("unchecked")
    public synchronized void loadFromYamlOrCreate() {
        try {
            Path file = yamlConfigFilePath();
            Files.createDirectories(file.getParent());
            if (!Files.isRegularFile(file)) {
                // No file yet: write current defaults to YAML
                saveToYaml();
                return;
            }
            String content = Files.readString(file, StandardCharsets.UTF_8);
            if (content == null || content.isBlank()) return;
            Yaml yaml = new Yaml();
            Object root = yaml.load(content);
            if (!(root instanceof java.util.Map<?,?> map)) return;

            // Helper lambdas for typed extraction
            java.util.function.Function<String, Object> get = k -> map.getOrDefault(k, null);
            java.util.function.Function<String, Boolean> getBool = k -> {
                Object v = get.apply(k);
                if (v instanceof Boolean b) return b;
                if (v instanceof String s) return Boolean.parseBoolean(s);
                if (v instanceof Number n) return n.intValue() != 0;
                return null;
            };
            java.util.function.Function<String, Integer> getInt = k -> {
                Object v = get.apply(k);
                if (v instanceof Number n) return n.intValue();
                if (v instanceof String s) {
                    try { return Integer.parseInt(s.trim()); } catch (Exception ignored) {}
                }
                return null;
            };
            java.util.function.Function<String, String> getStr = k -> {
                Object v = get.apply(k);
                return v == null ? null : String.valueOf(v);
            };

            Boolean b;
            Integer i;
            String s;

            if ((b = getBool.apply("scopeOnly")) != null) setScopeOnly(b);
            if ((i = getInt.apply("autoSaveSeconds")) != null) setAutoSaveSeconds(i);
            if ((i = getInt.apply("maxInlineJsKb")) != null) setMaxInlineJsKb(i);
            if ((i = getInt.apply("maxQueueSize")) != null) setMaxQueueSize(i);
            if ((i = getInt.apply("workerThreads")) != null) setWorkerThreads(i);

            if ((s = getStr.apply("exportDir")) != null && !s.isBlank()) setExportDir(Paths.get(s));
            if ((s = getStr.apply("globalExportDir")) != null && !s.isBlank()) setGlobalExportDir(Paths.get(s));

            if ((b = getBool.apply("overwriteOnSave")) != null) setOverwriteOnSave(b);
            if ((s = getStr.apply("snapshotNamePrefix")) != null) setSnapshotNamePrefix(s);
            if ((b = getBool.apply("loadPreviousOnStartup")) != null) setLoadPreviousOnStartup(b);

            if ((b = getBool.apply("enableJsluice")) != null) setEnableJsluice(b);
            if ((s = getStr.apply("goBinDir")) != null && !s.isBlank()) setGoBinDir(Paths.get(s));
            if ((i = getInt.apply("jsluiceTimeoutSec")) != null) setJsluiceTimeoutSec(i);
            if ((i = getInt.apply("jsluiceWorkers")) != null) setJsluiceWorkers(i);
            if ((i = getInt.apply("maxJsluiceFileMb")) != null) setMaxJsluiceFileMb(i);
            if ((s = getStr.apply("jsluiceStoreSubdir")) != null && !s.isBlank()) setJsluiceStoreSubdir(s);

            if ((s = getStr.apply("lastProjectName")) != null) setLastProjectName(s);
        } catch (Throwable ignored) {
        }
    }

    public synchronized void saveToYaml() {
        try {
            java.util.Map<String,Object> m = new java.util.LinkedHashMap<>();
            m.put("scopeOnly", isScopeOnly());
            m.put("autoSaveSeconds", getAutoSaveSeconds());
            m.put("maxInlineJsKb", getMaxInlineJsKb());
            m.put("maxQueueSize", getMaxQueueSize());
            m.put("workerThreads", getWorkerThreads());
            m.put("exportDir", getExportDir() == null ? null : getExportDir().toString());
            m.put("globalExportDir", getGlobalExportDir() == null ? null : getGlobalExportDir().toString());
            m.put("overwriteOnSave", isOverwriteOnSave());
            m.put("snapshotNamePrefix", getSnapshotNamePrefix());
            m.put("loadPreviousOnStartup", isLoadPreviousOnStartup());
            m.put("enableJsluice", isEnableJsluice());
            m.put("goBinDir", getGoBinDir() == null ? null : getGoBinDir().toString());
            m.put("jsluiceTimeoutSec", getJsluiceTimeoutSec());
            m.put("jsluiceWorkers", getJsluiceWorkers());
            m.put("maxJsluiceFileMb", getMaxJsluiceFileMb());
            m.put("jsluiceStoreSubdir", getJsluiceStoreSubdir());
            m.put("lastProjectName", getLastProjectName());

            DumperOptions opts = new DumperOptions();
            opts.setPrettyFlow(true);
            opts.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            Yaml yaml = new Yaml(opts);
            String out = yaml.dump(m);
            Path file = yamlConfigFilePath();
            Files.createDirectories(file.getParent());
            Files.writeString(file, out, StandardCharsets.UTF_8);
        } catch (Throwable ignored) {}
    }

    // Global ignored JS source patterns persistence (substring match against JS URL)
    public Path globalIgnoredSourcesFilePath() { return globalExportDir.resolve("paramamador_ignored.txt"); }
    public synchronized void loadGlobalIgnoredSourcesFromGlobalDir() {
        try {
            Path file = globalIgnoredSourcesFilePath();
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
                synchronized (globalIgnoredSources) {
                    globalIgnoredSources.clear();
                    globalIgnoredSources.addAll(cleaned);
                }
            } else {
                saveGlobalIgnoredSourcesToGlobalDir();
            }
        } catch (Throwable ignored) {}
    }
    public synchronized void saveGlobalIgnoredSourcesToGlobalDir() {
        try {
            Path file = globalIgnoredSourcesFilePath();
            Files.createDirectories(file.getParent());
            List<String> vals;
            synchronized (globalIgnoredSources) { vals = new ArrayList<>(globalIgnoredSources); }
            Files.write(file, vals, StandardCharsets.UTF_8);
        } catch (Throwable ignored) {}
    }

    // Global ignored endpoint values persistence (exact match against endpoint string)
    public Path globalIgnoredValuesFilePath() { return globalExportDir.resolve("paramamador_global_ignored.txt"); }
    public synchronized void loadGlobalIgnoredValuesFromGlobalDir() {
        try {
            Path file = globalIgnoredValuesFilePath();
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
                saveGlobalIgnoredValuesToGlobalDir();
            }
        } catch (Throwable ignored) {}
    }
    public synchronized void saveGlobalIgnoredValuesToGlobalDir() {
        try {
            Path file = globalIgnoredValuesFilePath();
            Files.createDirectories(file.getParent());
            List<String> vals;
            synchronized (globalIgnoredValues) { vals = new ArrayList<>(globalIgnoredValues); }
            Files.write(file, vals, StandardCharsets.UTF_8);
        } catch (Throwable ignored) {}
    }
}
