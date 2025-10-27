package burp.paramamador.integrations;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.scope.Scope;
import burp.paramamador.Settings;
import burp.paramamador.datastore.DataStore;
import burp.paramamador.datastore.EndpointRecord;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Background integration with BishopFox jsluice for AST-based JS scraping.
 * This service manages a queue of JS bodies (already captured by the plugin),
 * writes them to files under exportDir/jsluice_js, invokes jsluice, parses
 * the output and updates the in-memory store.
 */
public class JsluiceService {
    private final DataStore store;
    private final Settings settings;
    private final Scope scope;
    private final Logging log;

    private final ExecutorService executor;
    private final BlockingQueue<JsluiceTask> queue;
    private final AtomicBoolean started = new AtomicBoolean(false);

    private volatile Path jsluiceBinary;

    private static final ConcurrentHashMap<String, String> SCANNED_HASH_TO_URL = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, String> SCANNED_HASH_TO_REFERER = new ConcurrentHashMap<>();
    private static final Object SCANNED_FILE_LOCK = new Object();
    private static final Pattern FULL_URL = Pattern.compile("(?i)(https?://[^\\s\"'<>]+)");

    private final java.util.List<JsluiceUrlRecord> results = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
    private final java.util.Set<String> resultKeys = new java.util.concurrent.ConcurrentSkipListSet<>();

    public JsluiceService(DataStore store, Settings settings, Scope scope, Logging log) {
        this.store = store;
        this.settings = settings;
        this.scope = scope;
        this.log = log;
        this.queue = new LinkedBlockingQueue<>(Math.max(100, settings.getMaxQueueSize()));
        this.executor = Executors.newFixedThreadPool(Math.max(1, settings.getJsluiceWorkers()), r -> {
            Thread t = new Thread(r, "paramamador-jsluice-worker");
            t.setDaemon(true);
            return t;
        });
    }

    public void tryInit() {
        try {
            this.jsluiceBinary = resolveJsluiceBinary();
            if (this.jsluiceBinary == null) {
                log.logToOutput("jsluice not found; AST scanning disabled.");
                return;
            }
            // Ensure store dir exists
            Files.createDirectories(settings.jsluiceStoreDir());
            // Load previous scanned list
            loadScanned(settings.jsluiceScannedFilePath());
            // Attempt to load previously saved jsluice results from disk
            loadSavedResultsFromDir();
            // Start worker loop
            if (started.compareAndSet(false, true)) {
                for (int i = 0; i < settings.getJsluiceWorkers(); i++) {
                    executor.submit(this::workerLoop);
                }
            }
            log.logToOutput("jsluice enabled at: " + this.jsluiceBinary);
        } catch (Throwable t) {
            log.logToError("Failed to initialize jsluice: " + t.getMessage());
        }
    }

    public void shutdown() {
        try { executor.shutdownNow(); } catch (Throwable ignored) {}
    }

    public void enqueue(String sourceUrl, String referer, String jsBody, boolean inScopeHint) {
        if (!settings.isEnableJsluice()) return;
        if (jsBody == null || jsBody.isBlank()) return;
        if (jsluiceBinary == null) return; // not available

        try {
            // compute hash of the target JS file and put it with the source URL to the HashMap to scan twice
            String hash = sha256Hex(jsBody);
            if (hash == null) return;
            String prev = SCANNED_HASH_TO_URL.putIfAbsent(hash, sourceUrl == null ? "" : sourceUrl);
            if (prev != null) return; // already processed

            // Size limit
            if ((jsBody.length() / (1024 * 1024.0)) > settings.getMaxJsluiceFileMb()) {
                log.logToOutput("jsluice skip large JS (" + String.format(Locale.ROOT, "%.2f", jsBody.length() / (1024*1024.0)) + " MB): " + sourceUrl);
                return;
            }

            // Put mapping (hash, sourceUrl, referer) into the paramamador_jsluice_scanned.txt file
            tryAppendScanned(hash, sourceUrl, referer);

            // Put full content of the scanned JS file inside the jsluice_js dir for further scanning with the jsluice bin. 
            // Filename = SHA256 hash of the content.
            Path file = settings.jsluiceStoreDir().resolve(hash + ".js");
            if (!Files.isRegularFile(file)) {
                Files.createDirectories(file.getParent());
                Files.writeString(file, jsBody, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            }

            boolean offered = queue.offer(new JsluiceTask(sourceUrl, referer, file, hash, inScopeHint));
            if (!offered) {
                log.logToOutput("jsluice queue full; dropping: " + sourceUrl);
            }
        } catch (Throwable t) {
            log.logToError("jsluice enqueue failed: " + t.getMessage());
        }
    }

    private void workerLoop() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                JsluiceTask t = queue.poll(2, TimeUnit.SECONDS);
                if (t == null) continue;
                runJsluice(t);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            } catch (Throwable ex) {
                log.logToError("jsluice worker error: " + ex.getMessage());
            }
        }
    }

    private void runJsluice(JsluiceTask t) {
        if (jsluiceBinary == null || t == null) return;
        Process proc = null;
        try {
            // Use 'urls' subcommand which emits NDJSON lines per URL finding
            ProcessBuilder pb = new ProcessBuilder(jsluiceBinary.toString(), "urls", t.file().toString());
            pb.redirectErrorStream(true);
            proc = pb.start();
            boolean finished = proc.waitFor(settings.getJsluiceTimeoutSec(), TimeUnit.SECONDS);
            if (!finished) {
                proc.destroyForcibly();
                log.logToError("jsluice timed out for: " + t.file());
                return;
            }
            StringBuilder out = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) out.append(line).append('\n');
            }
            String stdout = out.toString();
            if (stdout == null || stdout.isBlank()) return;

            // Save raw NDJSON results to results directory
            try {
                Path resultsDir = settings.jsluiceResultsDir();
                Files.createDirectories(resultsDir);
                Path outFile = resultsDir.resolve(t.hash() + ".json");
                Files.writeString(outFile, stdout, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            } catch (Throwable ioe) {
                log.logToError("Failed to save jsluice results: " + ioe.getMessage());
            }

            parseAndStoreNdjson(stdout, t.sourceUrl(), t.referer(), t.inScopeHint());
        } catch (Throwable e) {
            log.logToError("jsluice exec error: " + e.getMessage());
        } finally {
            if (proc != null) {
                try { proc.destroy(); } catch (Throwable ignored) {}
            }
        }
    }

    private void parseAndStoreNdjson(String ndjson, String sourceUrl, String referer, boolean inScopeHint) {
        try {
            String[] lines = ndjson.split("\r?\n");
            for (String line : lines) {
                if (line == null) continue;
                String t = line.trim();
                if (t.isEmpty()) continue;
                JsonObject obj;
                try {
                    obj = JsonParser.parseString(t).getAsJsonObject();
                } catch (Throwable pe) {
                    continue;
                }
                String url = obj.has("url") && !obj.get("url").isJsonNull() ? obj.get("url").getAsString() : null;
                String method = obj.has("method") && !obj.get("method").isJsonNull() ? obj.get("method").getAsString() : "";
                String type = obj.has("type") && !obj.get("type").isJsonNull() ? obj.get("type").getAsString() : "";
                String filename = obj.has("filename") && !obj.get("filename").isJsonNull() ? obj.get("filename").getAsString() : "";
                String contentType = obj.has("contentType") && !obj.get("contentType").isJsonNull() ? obj.get("contentType").getAsString() : null;

                java.util.List<String> qparams = new java.util.ArrayList<>();
                if (obj.has("queryParams") && obj.get("queryParams").isJsonArray()) {
                    for (JsonElement e : obj.get("queryParams").getAsJsonArray()) {
                        if (e != null && e.isJsonPrimitive()) qparams.add(e.getAsString());
                    }
                }
                java.util.List<String> bparams = new java.util.ArrayList<>();
                if (obj.has("bodyParams") && obj.get("bodyParams").isJsonArray()) {
                    for (JsonElement e : obj.get("bodyParams").getAsJsonArray()) {
                        if (e != null && e.isJsonPrimitive()) bparams.add(e.getAsString());
                    }
                }
                java.util.Map<String,String> headers = new java.util.LinkedHashMap<>();
                if (obj.has("headers") && obj.get("headers").isJsonObject()) {
                    for (Map.Entry<String, JsonElement> en : obj.get("headers").getAsJsonObject().entrySet()) {
                        try { headers.put(en.getKey(), en.getValue().getAsString()); } catch (Throwable ignored) {}
                    }
                }

                // Persist parameters into main store (mark as js AST)
                for (String p : qparams) {
                    if (p != null && !p.isBlank()) {
                        store.addOrUpdateParam(p, safeHost(sourceUrl), "js_ast", null);
                        store.markOnlyInCode(p, "jsluice");
                    }
                }
                for (String p : bparams) {
                    if (p != null && !p.isBlank()) {
                        store.addOrUpdateParam(p, safeHost(sourceUrl), "js_ast", null);
                        store.markOnlyInCode(p, "jsluice");
                    }
                }
                // Derive and store params from URL query
                if (url != null) {
                    int qpos = url.indexOf('?');
                    if (qpos >= 0 && qpos + 1 < url.length()) {
                        String qs = url.substring(qpos + 1);
                        for (String part : qs.split("&")) {
                            int eq = part.indexOf('=');
                            String name = eq > 0 ? part.substring(0, eq) : part;
                            if (!name.isBlank()) {
                                store.addOrUpdateParam(name, safeHost(sourceUrl), "js_ast", null);
                                store.markOnlyInCode(name, "jsluice");
                            }
                        }
                    }
                }

                // Keep jsluice endpoints out of main endpoints table; store them in this service only
                String key = (url == null ? "" : url) + "|" + method + "|" + type + "|" + filename;
                if (resultKeys.add(key)) {
                    results.add(new JsluiceUrlRecord(url, qparams, bparams, method, type, filename, contentType, headers, sourceUrl, referer));
                }
            }
        } catch (Throwable e) {
            log.logToError("jsluice NDJSON parse error: " + e.getMessage());
        }
    }

    private boolean isUrlInScope(String url) {
        if (url == null || url.isBlank()) return false;
        try { return scope.isInScope(url); } catch (Throwable t) { return false; }
    }

    private static String safeHost(String url) {
        try {
            java.net.URI u = java.net.URI.create(url == null ? "" : url);
            return (u.getHost() == null ? "" : u.getHost()) + " " + (u.getPath() == null ? "" : u.getPath());
        } catch (Throwable t) { return ""; }
    }

    private static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Throwable e) {
            return null;
        }
    }

    private void tryAppendScanned(String hash, String url, String referer) {
        try {
            Path file = settings.jsluiceScannedFilePath();
            Files.createDirectories(file.getParent());
            String line = (hash == null ? "" : hash)
                    + "\t" + (url == null ? "" : url)
                    + "\t" + (referer == null ? "" : referer)
                    + System.lineSeparator();
            synchronized (SCANNED_FILE_LOCK) {
                Files.writeString(file, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }
        } catch (Throwable ignored) {}
    }

    private void loadSavedResultsFromDir() {
        try {
            Path dir = settings.jsluiceResultsDir();
            if (dir == null || !Files.isDirectory(dir)) return;
            try (java.util.stream.Stream<Path> stream = Files.list(dir)) {
                stream.filter(p -> p != null && p.getFileName() != null && p.toString().toLowerCase(Locale.ROOT).endsWith(".json"))
                        .forEach(p -> {
                            try {
                                String fileName = p.getFileName().toString();
                                String hash = fileName.substring(0, Math.max(0, fileName.length() - ".json".length()));
                                String sourceUrl = SCANNED_HASH_TO_URL.get(hash);
                                String referer = SCANNED_HASH_TO_REFERER.get(hash);
                                String ndjson = Files.readString(p, StandardCharsets.UTF_8);
                                boolean inScope = isUrlInScope(sourceUrl);
                                if (ndjson != null && !ndjson.isBlank()) {
                                    parseAndStoreNdjson(ndjson, sourceUrl, referer, inScope);
                                }
                            } catch (Throwable ignored) {}
                        });
            }
        } catch (Throwable ignored) {}
    }

    private void loadScanned(Path file) {
        if (file == null) return;
        try {
            if (!Files.isRegularFile(file)) return;
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            for (String line : lines) {
                if (line == null) continue;
                String t = line.trim();
                if (t.isEmpty()) continue;
                // Support legacy format: "url\t<hash>" and new format: "<hash>\t<url>\t<referer>"
                String[] parts = t.split("\t");
                if (parts.length >= 2) {
                    String hash;
                    String url;
                    String referer = null;
                    if (isLikelyHash(parts[0])) {
                        hash = parts[0].trim();
                        url = parts[1].trim();
                        if (parts.length >= 3) referer = parts[2].trim();
                    } else if (isLikelyHash(parts[1])) {
                        url = parts[0].trim();
                        hash = parts[1].trim();
                    } else {
                        continue;
                    }
                    if (!hash.isEmpty()) SCANNED_HASH_TO_URL.putIfAbsent(hash, url);
                    if (referer != null && !referer.isEmpty()) SCANNED_HASH_TO_REFERER.putIfAbsent(hash, referer);
                }
            }
        } catch (Throwable ignored) {}
    }

    private static boolean isLikelyHash(String s) {
        if (s == null) return false;
        String t = s.trim();
        if (t.length() < 32) return false;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) return false;
        }
        return true;
    }

    private Path resolveJsluiceBinary() {
        try {
            // 1) user-provided go bin dir
            Path p = settings.getGoBinDir();
            if (p != null) {
                Path cand = p.resolve(binaryName());
                if (Files.isExecutable(cand)) return cand;
            }
            // 2) $GOBIN
            String gobin = System.getenv("GOBIN");
            if (gobin != null && !gobin.isBlank()) {
                Path cand = Path.of(gobin).resolve(binaryName());
                if (Files.isExecutable(cand)) return cand;
            }
            // 3) $GOPATH/bin
            String gopath = System.getenv("GOPATH");
            if (gopath != null && !gopath.isBlank()) {
                Path cand = Path.of(gopath, "bin").resolve(binaryName());
                if (Files.isExecutable(cand)) return cand;
            }
            // 4) $HOME/go/bin
            String home = System.getProperty("user.home");
            if (home != null) {
                Path cand = Path.of(home, "go", "bin").resolve(binaryName());
                if (Files.isExecutable(cand)) return cand;
            }
            // 5) PATH fallback
            try {
                Process which = new ProcessBuilder(osIsWindows() ? new String[]{"where", "jsluice"} : new String[]{"which", "jsluice"}).start();
                which.waitFor(2, TimeUnit.SECONDS);
                try (BufferedReader r = new BufferedReader(new InputStreamReader(which.getInputStream(), StandardCharsets.UTF_8))) {
                    String line = r.readLine();
                    if (line != null && !line.isBlank()) {
                        Path cand = Path.of(line.trim());
                        if (Files.isExecutable(cand)) return cand;
                    }
                }
            } catch (Throwable ignored) {}
        } catch (Throwable ignored) {}
        return null;
    }

    private static boolean osIsWindows() {
        String os = System.getProperty("os.name", "");
        return os.toLowerCase(Locale.ROOT).contains("win");
    }

    private static String binaryName() {
        return osIsWindows() ? "jsluice.exe" : "jsluice";
    }

    public java.util.List<JsluiceUrlRecord> snapshotResults() {
        synchronized (results) {
            return new java.util.ArrayList<>(results);
        }
    }

    public record JsluiceTask(String sourceUrl, String referer, Path file, String hash, boolean inScopeHint) {}
}
