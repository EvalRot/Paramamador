package burp.paramamador;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.settings.*;

import burp.paramamador.analyzer.JsEndpointAnalyzer;
import burp.paramamador.analyzer.ParameterAnalyzer;
import burp.paramamador.datastore.DataStore;
import burp.paramamador.scanner.SiteTreeScanner;
import burp.paramamador.ui.ParamamadorTab;
import burp.paramamador.util.IOUtils;
import burp.paramamador.integrations.JsluiceService;

import javax.swing.*;
import java.awt.*;
import java.time.Instant;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.nio.file.Path;

/**
 * Paramamador Burp extension main entry point.
 */
public class Extension implements BurpExtension {

    private MontoyaApi api;
    private Logging log;
    private UserInterface ui;
    private Scope scope;
    private SiteMap siteMap;

    private final DataStore store = new DataStore();
    private final Settings settings = new Settings();

    private LinkedBlockingQueue<JsTask> jsQueue;
    private ExecutorService jsExecutor;
    private ScheduledExecutorService scheduler;

    private Registration httpHandlerReg;
    private Registration suiteTabReg;
    private Registration settingsPanelReg;
    private Registration contextMenuReg;
    private Registration unloadReg;

    private ParamamadorTab tab;
    private SiteTreeScanner siteTreeScanner;
    private JsluiceService jsluiceService;

    private final AtomicBoolean started = new AtomicBoolean(false);

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        this.log = api.logging();
        this.ui = api.userInterface();
        this.scope = api.scope();
        this.siteMap = api.siteMap();

        api.extension().setName("Paramamador");
        log.logToOutput("Paramamador loaded (" + Instant.now() + ")");

        // Load YAML settings early (create with defaults if missing)
        try {
            settings.loadFromYamlOrCreate();
        } catch (Throwable t) {
            log.logToError("Failed to load YAML settings: " + t.getMessage());
        }

        // Prepare Fixed thread pool for parallel analysis of heavy JS files (> settings.maxInlineJsKb)
        this.jsExecutor = Executors.newFixedThreadPool(settings.getWorkerThreads(), r -> {
            Thread t = new Thread(r, "paramamador-js-worker");
            t.setDaemon(true);
            return t;
        });
        // The queue for storing heavy JS files for analysis via jsExecutor
        this.jsQueue = new LinkedBlockingQueue<>(settings.getMaxQueueSize());
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "paramamador-scheduler");
            t.setDaemon(true);
            return t;
        });

        // Initial user setup (export dir, filename base)
        try {
            showInitialSetupDialog();
        } catch (Throwable t) {
            log.logToError("Initial setup dialog failed: " + t.getMessage());
        }

        // Load GLOBAL ignore lists from the chosen global export dir
        try {
            settings.loadGlobalIgnoredSourcesFromGlobalDir();
            settings.loadGlobalIgnoredValuesFromGlobalDir();
        } catch (Throwable t) {
            log.logToError("Failed to load ignore lists: " + t.getMessage());
        }

        // Load previously scanned JS URL+hash list for content dedupe
        try {
            burp.paramamador.analyzer.JsEndpointAnalyzer.loadProcessedFromFile(settings.scannedJsFilePath());
        } catch (Throwable t) {
            log.logToError("Failed to load scanned JS list: " + t.getMessage());
        }

        // RefererTracker removed; rely on endpoint-level referers and jsluice scanned index

        // Load variable defaults for :vars in endpoints
        try {
            settings.loadVariableDefaultsFromFile();
        } catch (Throwable t) {
            log.logToError("Failed to load variable defaults: " + t.getMessage());
        }

        // Load default request headers
        try {
            settings.loadDefaultHeadersFromFile();
        } catch (Throwable t) {
            log.logToError("Failed to load default headers: " + t.getMessage());
        }

        // Initialize jsluice integration (if enabled)
        if (settings.isEnableJsluice()) {
            try {
                this.jsluiceService = new JsluiceService(store, settings, scope, log);
                this.jsluiceService.tryInit();
            } catch (Throwable t) {
                log.logToError("Failed to init jsluice service: " + t.getMessage());
            }
        }

        // Start scheduled autosave
        scheduler.scheduleAtFixedRate(this::saveAllSafe, settings.getAutoSaveSeconds(), settings.getAutoSaveSeconds(), TimeUnit.SECONDS);

        // Optionally load previous session JSONs from export dir (user opt-in)
        try {
            if (settings.isLoadPreviousOnStartup()) {
                java.nio.file.Path dir = settings.getExportDir();
                java.util.List<java.nio.file.Path> jsons = new java.util.ArrayList<>();
                try (java.util.stream.Stream<java.nio.file.Path> stream = java.nio.file.Files.list(dir)) {
                    stream.filter(p -> p != null && p.toString().toLowerCase().endsWith(".json")).forEach(jsons::add);
                }
                if (!jsons.isEmpty()) {
                    store.loadFromFiles(jsons);
                }
            }
        } catch (Throwable t) {
            log.logToError("Failed to load previous results: " + t.getMessage());
        }

        // Create startup snapshot files with project name + timestamp or user-provided base
        try {
            createStartupSnapshots();
        } catch (Throwable t) {
            log.logToError("Startup snapshot creation failed: " + t.getMessage());
        }

        // Periodically refresh UI so new data appears in tables
        scheduler.scheduleAtFixedRate(() -> {
            try {
                if (tab != null) {
                    tab.refreshAll();
                }
            } catch (Throwable t) {
                log.logToError("UI refresh error: " + t.getMessage());
            }
        }, 15, 15, TimeUnit.SECONDS);

        // Build UI
        this.tab = new ParamamadorTab(store, settings, () -> {
            // Rescan action from UI
            try {
                siteTreeScanner.rescanSiteTree();
            } catch (Throwable t) {
                log.logToError("Rescan failed: " + t.getMessage());
            }
        }, this::saveAllSafe, jsluiceService,
                // Sender to Repeater for the Send-to-Repeater dialog
                (req) -> {
                    try {
                        api.repeater().sendToRepeater(req, "Paramamador");
                    } catch (Throwable t) {
                        log.logToError("Send to Repeater failed: " + t.getMessage());
                    }
                },
                // Latest Authorization header by host
                (hostOnly) -> {
                    try {
                        var list = api.proxy().history();
                        for (int i = list.size() - 1; i >= 0; i--) {
                            var rr = list.get(i);
                            String h = rr.request().headerValue("Host");
                            if (hostMatches(h, hostOnly)) {
                                String val = rr.request().headerValue("Authorization");
                                if (val != null && !val.isBlank()) return val;
                            }
                        }
                    } catch (Throwable ignored) {}
                    return null;
                },
                // Latest Cookie header by host
                (hostOnly) -> {
                    try {
                        var list = api.proxy().history();
                        for (int i = list.size() - 1; i >= 0; i--) {
                            var rr = list.get(i);
                            String h = rr.request().headerValue("Host");
                            if (hostMatches(h, hostOnly)) {
                                String val = rr.request().headerValue("Cookie");
                                if (val != null && !val.isBlank()) return val;
                            }
                        }
                    } catch (Throwable ignored) {}
                    return null;
                },
                // Site Map URLs by host (like "Copy URLs in this host")
                (hostOnly) -> {
                    java.util.List<String> urls = new java.util.ArrayList<>();
                    try {
                        for (var rr : api.siteMap().requestResponses()) {
                            try {
                                String url = rr.request().url();
                                if (url == null || url.isBlank()) continue;
                                String headerHost = rr.request().headerValue("Host");
                                String parsedHost = safeParseHostPort(url);
                                if (hostMatches(headerHost, hostOnly) || hostMatches(parsedHost, hostOnly)) {
                                    urls.add(url);
                                }
                            } catch (Throwable ignored) {}
                        }
                    } catch (Throwable ignored) {}
                    return urls;
                },
                // Latest Authorization/Cookie from the same recent request (limit 10) for host
                (hostOnly) -> {
                    java.util.Map<String,String> m = new java.util.LinkedHashMap<>();
                    try {
                        var list = api.proxy().history();
                        int seenForHost = 0;
                        for (int i = list.size() - 1; i >= 0; i--) {
                            var rr = list.get(i);
                            String h = rr.request().headerValue("Host");
                            if (!hostMatches(h, hostOnly)) continue;
                            seenForHost++;
                            String cookie = rr.request().headerValue("Cookie");
                            String auth = rr.request().headerValue("Authorization");
                            if ((cookie != null && !cookie.isBlank()) || (auth != null && !auth.isBlank())) {
                                if (cookie != null && !cookie.isBlank()) m.put("Cookie", cookie);
                                if (auth != null && !auth.isBlank()) m.put("Authorization", auth);
                                break;
                            }
                            if (seenForHost >= 10) break;
                        }
                    } catch (Throwable ignored) {}
                    return m;
                }
        );
        this.suiteTabReg = ui.registerSuiteTab("paramamador", tab.getComponent());

        // Settings panel (persisted by Burp). Keys are human-readable.
        SettingsPanelWithData settingsPanel = SettingsPanelBuilder.settingsPanel()
                .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
                .withTitle("Paramamador Settings")
                .withDescription("Configure background processing, autosave and ignore patterns.")
                .withSettings(
                        SettingsPanelSetting.booleanSetting("Scope only", settings.isScopeOnly()),
                        SettingsPanelSetting.integerSetting("Auto-save interval (sec)", settings.getAutoSaveSeconds()),
                        SettingsPanelSetting.integerSetting("Max inline JS size (KB)", settings.getMaxInlineJsKb()),
                        SettingsPanelSetting.integerSetting("Max queue size", settings.getMaxQueueSize()),
                        // Use a simple comma-separated string instead of listSetting to avoid default value issues
                        SettingsPanelSetting.stringSetting(
                                "Global ignored sources (comma-separated)",
                                String.join(",", settings.getGlobalIgnoredSources())
                        )
                )
                .build();
        this.settingsPanelReg = ui.registerSettingsPanel(settingsPanel);

        // Context menu items provider (simple integration)
        this.contextMenuReg = ui.registerContextMenuItemsProvider(new SimpleContextMenuProvider());

        // Site tree scanner depends on API + analyzers
        JsEndpointAnalyzer jsAnalyzer = new JsEndpointAnalyzer(store, settings, scope, log);
        this.siteTreeScanner = new SiteTreeScanner(api, jsAnalyzer, settings, store, log, jsluiceService);

        // Register HTTP handler for passive analysis
        this.httpHandlerReg = api.http().registerHttpHandler(new PassiveHttpHandler());

        // Unloading handler to stop threads and flush data
        this.unloadReg = api.extension().registerUnloadingHandler((ExtensionUnloadingHandler) () -> {
            try {
                shutdown();
            } catch (Throwable t) {
                log.logToError("Error during unload: " + t.getMessage());
            }
        });

        started.set(true);
    }

    private static boolean hostMatches(String headerHost, String targetHost) {
        if (headerHost == null || targetHost == null) return false;
        String a = headerHost.trim().toLowerCase(java.util.Locale.ROOT);
        String b = targetHost.trim().toLowerCase(java.util.Locale.ROOT);
        if (a.equals(b)) return true;
        // If one has explicit port and the other doesn't, compare hostnames only
        String ahost = a;
        String bhost = b;
        int ai = a.indexOf(':');
        if (ai >= 0) ahost = a.substring(0, ai);
        int bi = b.indexOf(':');
        if (bi >= 0) bhost = b.substring(0, bi);
        return ahost.equals(bhost);
    }

    private static String originOnly(String url) {
        try {
            if (url == null || url.isBlank()) return url;
            java.net.URI u = java.net.URI.create(url);
            String scheme = u.getScheme();
            String host = u.getHost();
            if (scheme == null || host == null || host.isBlank()) return url;
            int port = u.getPort();
            return scheme + "://" + host + (port > 0 ? ":" + port : "");
        } catch (Throwable ignored) {
            return url;
        }
    }

    private static String safeParseHostPort(String url) {
        try {
            if (url == null || url.isBlank()) return null;
            java.net.URI u = java.net.URI.create(url);
            String h = u.getHost();
            if (h == null || h.isBlank()) return null;
            int p = u.getPort();
            return p > 0 ? h + ":" + p : h;
        } catch (Throwable t) { return null; }
    }

    private void shutdown() {
        saveAllSafe();
        if (httpHandlerReg != null) httpHandlerReg.deregister();
        if (suiteTabReg != null) suiteTabReg.deregister();
        if (settingsPanelReg != null) settingsPanelReg.deregister();
        if (contextMenuReg != null) contextMenuReg.deregister();
        if (unloadReg != null) unloadReg.deregister();
        if (scheduler != null) scheduler.shutdownNow();
        if (jsExecutor != null) jsExecutor.shutdownNow();
        if (jsluiceService != null) jsluiceService.shutdown();
        log.logToOutput("Paramamador unloaded");
    }

    private void saveAllSafe() {
        try {
            // Ensure we have current timestamp-based snapshot files under the active export dir
            Path paramsFile = settings.getCurrentParametersFile();
            Path endpointsFile = settings.getCurrentEndpointsFile();
            Path exportDir = settings.getExportDir();
            boolean needNew = (paramsFile == null || endpointsFile == null);
            if (!needNew) {
                try {
                    needNew = (paramsFile.getParent() == null || !paramsFile.getParent().equals(exportDir))
                            || (endpointsFile.getParent() == null || !endpointsFile.getParent().equals(exportDir));
                } catch (Throwable ignored) {}
            }

            if (needNew) {
                createStartupSnapshots();
                paramsFile = settings.getCurrentParametersFile();
                endpointsFile = settings.getCurrentEndpointsFile();
            }

            if (paramsFile != null) IOUtils.ensureDir(paramsFile.getParent());
            if (endpointsFile != null) IOUtils.ensureDir(endpointsFile.getParent());

            store.saveToDisk(paramsFile, endpointsFile);
        } catch (Throwable t) {
            log.logToError("Save failed: " + t.getMessage());
        }
    }

    private void createStartupSnapshots() {
        // Look for existing snapshot files in exportDir. Use them if exactly one exists per group.
        // If multiple exist in a group, merge only that group into a single file and delete the old ones.
        // If none exist in a group, create a fresh file for that group.
        try {
            IOUtils.ensureDir(settings.getExportDir());
        } catch (java.io.IOException ioe) {
            throw new RuntimeException(ioe);
        }

        String base = settings.getSnapshotNamePrefix();
        if (base == null || base.isBlank()) base = settings.getLastProjectName();
        if (base == null || base.isBlank()) base = "project";
        String ts = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());

        java.nio.file.Path dir = settings.getExportDir();
        java.util.List<java.nio.file.Path> paramFiles = new java.util.ArrayList<>();
        java.util.List<java.nio.file.Path> endpointFiles = new java.util.ArrayList<>();
        try (java.util.stream.Stream<java.nio.file.Path> stream = java.nio.file.Files.list(dir)) {
            if (stream != null) {
                stream.filter(p -> p != null && java.nio.file.Files.isRegularFile(p) && p.getFileName() != null)
                        .forEach(p -> {
                            String name = p.getFileName().toString();
                            if (name.startsWith("paramamador_") && name.endsWith("_parameters.json")) {
                                paramFiles.add(p);
                            } else if (name.startsWith("paramamador_") && name.endsWith("_endpoints.json")) {
                                endpointFiles.add(p);
                            }
                        });
            }
        } catch (Throwable ignored) {}

        // Decide output files for each group independently
        java.nio.file.Path paramsOut;
        java.nio.file.Path endpointsOut;

        // Parameters group handling
        if (paramFiles.size() == 1) {
            paramsOut = paramFiles.get(0);
        } else if (paramFiles.size() > 1) {
            paramsOut = dir.resolve("paramamador_" + base + "_" + ts + "_parameters.json");
            try {
                DataStore mergeParams = new DataStore();
                mergeParams.loadFromFiles(paramFiles);
                mergeParams.saveToDisk(paramsOut, null);
                for (java.nio.file.Path p : paramFiles) {
                    try { if (!p.equals(paramsOut)) java.nio.file.Files.deleteIfExists(p); } catch (Throwable ignored) {}
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else {
            // none found: create fresh empty parameters file
            paramsOut = dir.resolve("paramamador_" + base + "_" + ts + "_parameters.json");
            try {
                new DataStore().saveToDisk(paramsOut, null);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        // Endpoints group handling
        if (endpointFiles.size() == 1) {
            endpointsOut = endpointFiles.get(0);
        } else if (endpointFiles.size() > 1) {
            endpointsOut = dir.resolve("paramamador_" + base + "_" + ts + "_endpoints.json");
            try {
                DataStore mergeEndpoints = new DataStore();
                mergeEndpoints.loadFromFiles(endpointFiles);
                mergeEndpoints.saveToDisk(null, endpointsOut);
                for (java.nio.file.Path p : endpointFiles) {
                    try { if (!p.equals(endpointsOut)) java.nio.file.Files.deleteIfExists(p); } catch (Throwable ignored) {}
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else {
            // none found: create fresh empty endpoints file
            endpointsOut = dir.resolve("paramamador_" + base + "_" + ts + "_endpoints.json");
            try {
                new DataStore().saveToDisk(null, endpointsOut);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        settings.setCurrentParametersFile(paramsOut);
        settings.setCurrentEndpointsFile(endpointsOut);
    }

    private void showInitialSetupDialog() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            try {
                JTextField nameField = new JTextField();
                String suggested = "";
                if (settings.getSnapshotNamePrefix() != null && !settings.getSnapshotNamePrefix().isBlank()) {
                    suggested = settings.getSnapshotNamePrefix();
                } else if (settings.getLastProjectName() != null && !settings.getLastProjectName().isBlank()) {
                    suggested = settings.getLastProjectName();
                }
                nameField.setText(suggested);

                JTextField dirField = new JTextField(settings.getExportDir().toString(), 30);
                JButton browse = new JButton("Browse...");
                browse.addActionListener(e -> {
                    JFileChooser fc = new JFileChooser();
                    fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                    try { fc.setCurrentDirectory(settings.getExportDir().toFile()); } catch (Throwable ignored) {}
                    int res = fc.showOpenDialog(null);
                    if (res == JFileChooser.APPROVE_OPTION && fc.getSelectedFile() != null) {
                        dirField.setText(fc.getSelectedFile().getAbsolutePath());
                    }
                });

                JTextField globalDirField = new JTextField(settings.getGlobalExportDir().toString(), 30);
                JButton globalBrowse = new JButton("Browse...");
                globalBrowse.addActionListener(e -> {
                    JFileChooser fc = new JFileChooser();
                    fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                    try { fc.setCurrentDirectory(settings.getGlobalExportDir().toFile()); } catch (Throwable ignored) {}
                    int res = fc.showOpenDialog(null);
                    if (res == JFileChooser.APPROVE_OPTION && fc.getSelectedFile() != null) {
                        globalDirField.setText(fc.getSelectedFile().getAbsolutePath());
                    }
                });

                JCheckBox loadPrev = new JCheckBox("Load previous results from export directory");
                loadPrev.setSelected(settings.isLoadPreviousOnStartup());

                JCheckBox enableJsluice = new JCheckBox("Enable AST scanning with jsluice");
                enableJsluice.setSelected(settings.isEnableJsluice());

                JTextField goBinField = new JTextField(settings.getGoBinDir() == null ? "" : settings.getGoBinDir().toString(), 30);
                JButton goBinBrowse = new JButton("Browse...");
                goBinBrowse.addActionListener(e -> {
                    JFileChooser fc = new JFileChooser();
                    fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                    try { if (settings.getGoBinDir() != null) fc.setCurrentDirectory(settings.getGoBinDir().toFile()); } catch (Throwable ignored) {}
                    int res = fc.showOpenDialog(null);
                    if (res == JFileChooser.APPROVE_OPTION && fc.getSelectedFile() != null) {
                        goBinField.setText(fc.getSelectedFile().getAbsolutePath());
                    }
                });

                JPanel panel = new JPanel(new GridBagLayout());
                GridBagConstraints c = new GridBagConstraints();
                c.insets = new Insets(4,4,4,4);
                c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1;
                int row = 0;
                c.gridx = 0; c.gridy = row; panel.add(new JLabel("Project name"), c);
                c.gridx = 1; panel.add(nameField, c); row++;
                c.gridx = 0; c.gridy = row; panel.add(new JLabel("Export directory"), c);
                JPanel dirPanel = new JPanel(new BorderLayout());
                dirPanel.add(dirField, BorderLayout.CENTER);
                dirPanel.add(browse, BorderLayout.EAST);
                c.gridx = 1; panel.add(dirPanel, c); row++;

                c.gridx = 0; c.gridy = row; panel.add(new JLabel("Global export directory"), c);
                JPanel globalDirPanel = new JPanel(new BorderLayout());
                globalDirPanel.add(globalDirField, BorderLayout.CENTER);
                globalDirPanel.add(globalBrowse, BorderLayout.EAST);
                c.gridx = 1; panel.add(globalDirPanel, c); row++;

                // Load previous results checkbox
                c.gridx = 0; c.gridy = row; c.gridwidth = 2; panel.add(loadPrev, c); row++; c.gridwidth = 1;

                // jsluice enable + Go bin dir
                c.gridx = 0; c.gridy = row; c.gridwidth = 2; panel.add(enableJsluice, c); row++; c.gridwidth = 1;
                c.gridx = 0; c.gridy = row; panel.add(new JLabel("Go bin directory (optional)"), c);
                JPanel goBinPanel = new JPanel(new BorderLayout());
                goBinPanel.add(goBinField, BorderLayout.CENTER);
                goBinPanel.add(goBinBrowse, BorderLayout.EAST);
                c.gridx = 1; panel.add(goBinPanel, c); row++;

                int option = JOptionPane.showConfirmDialog(null, panel, "Paramamador Setup", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
                if (option == JOptionPane.OK_OPTION) {
                    String baseName = nameField.getText();
                    if (baseName != null && !baseName.isBlank()) {
                        settings.setSnapshotNamePrefix(baseName.trim());
                        settings.setLastProjectName(baseName.trim());
                    }
                    String dir = dirField.getText();
                    if (dir != null && !dir.isBlank()) settings.setExportDir(java.nio.file.Paths.get(dir.trim()));
                    String gdir = globalDirField.getText();
                    if (gdir != null && !gdir.isBlank()) settings.setGlobalExportDir(java.nio.file.Paths.get(gdir.trim()));
                    settings.setLoadPreviousOnStartup(loadPrev.isSelected());
                    settings.setEnableJsluice(enableJsluice.isSelected());
                    String goBin = goBinField.getText();
                    if (goBin != null && !goBin.isBlank()) settings.setGoBinDir(java.nio.file.Paths.get(goBin.trim()));
                    try { settings.saveToYaml(); } catch (Throwable ignored) {}
                }
            } catch (Throwable t) {
                log.logToError("Setup dialog error: " + t.getMessage());
            }
        });
    }

    // safeProjectName() removed; project name is persisted in YAML (lastProjectName) and set on first initialization.

    

    /** Simple background JS analysis task */
    private record JsTask(String sourceUrl, String referer, String body, boolean inScope) {}

    /** Passive HTTP handler; keep work light and offload heavy parsing. */
    private class PassiveHttpHandler implements HttpHandler {
        private final ParameterAnalyzer paramAnalyzer = new ParameterAnalyzer(store, settings, log);
        private final JsEndpointAnalyzer jsAnalyzer = new JsEndpointAnalyzer(store, settings, scope, log);

        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
            // Inline, lightweight parameter extraction from request
            try {
                paramAnalyzer.extractFromRequest(request);
            } catch (Throwable t) {
                log.logToError("Request analysis error: " + t.getMessage());
            }
            return RequestToBeSentAction.continueWith(request);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
            try {
                // Inline parameter extraction from response (cookies/JSON keys)
                paramAnalyzer.extractFromResponse(response.initiatingRequest(), response);

                // Detect JS and analyze endpoints
                String url = response.initiatingRequest() != null ? response.initiatingRequest().url() : "";
                String referer = null;
                if (response.initiatingRequest() != null) {
                    String ref = response.initiatingRequest().headerValue("Referer");
                    String origin = response.initiatingRequest().headerValue("Origin");
                    referer = (ref != null && !ref.isBlank()) ? ref : origin;
                }
                String ct = response.headerValue("Content-Type");
                boolean looksLikeJs = response.mimeType() == MimeType.SCRIPT
                        || (ct != null && ct.toLowerCase().contains("javascript"))
                        || (url != null && url.toLowerCase().endsWith(".js"));

                if (looksLikeJs) {
                    String body = response.bodyToString();
                    int sizeKb = body != null ? body.length() / 1024 : 0;
                    boolean inScope = response.initiatingRequest() != null && response.initiatingRequest().isInScope();
                    // Normalize referer to origin (scheme://host[:port])
                    referer = originOnly(referer);

                    // Enqueue for jsluice AST analysis if enabled
                    if (jsluiceService != null && body != null && !body.isBlank()) {
                        try { jsluiceService.enqueue(url, referer, body, inScope); } catch (Throwable ignored) {}
                    }

                    if (sizeKb <= settings.getMaxInlineJsKb()) {
                        jsAnalyzer.extractEndpoints(url, referer, body, inScope);
                    } else {
                        // Offload to background workers; drop on overload
                        boolean offered = jsQueue.offer(new JsTask(url, referer, body, inScope));
                        if (offered) {
                            jsExecutor.submit(() -> {
                                try {
                                    JsTask t = jsQueue.poll(1, TimeUnit.SECONDS);
                                    if (t != null) {
                                        jsAnalyzer.extractEndpoints(t.sourceUrl(), t.referer(), t.body(), t.inScope());
                                    }
                                } catch (InterruptedException ignored) {
                                    Thread.currentThread().interrupt();
                                } catch (Throwable ex) {
                                    log.logToError("JS analysis error: " + ex.getMessage());
                                }
                            });
                        } // else drop and continue
                    }
                }

            } catch (Throwable t) {
                log.logToError("Response analysis error: " + t.getMessage());
            }

            return ResponseReceivedAction.continueWith(response);
        }
    }

    /** Simple context menu to trigger analysis or ignore action. */
    private class SimpleContextMenuProvider implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            try {
                JMenuItem sendItem = new JMenuItem("Paramamador: Send to analyzer");
                sendItem.addActionListener(a -> {
                    try {
                        event.messageEditorRequestResponse().ifPresent(msg -> {
                            var req = msg.requestResponse().request();
                            var res = msg.requestResponse().response();
                            if (res != null) {
                                new PassiveHttpHandler().handleHttpResponseReceived(
                                        new HttpResponseReceivedWrapper(res, req)
                                );
                            }
                        });
                    } catch (Throwable t) {
                        log.logToError("Context analyze error: " + t.getMessage());
                    }
                });

                JMenuItem ignoreItem = new JMenuItem("Paramamador: Ignore this JS source");
                ignoreItem.addActionListener(a -> event.messageEditorRequestResponse().ifPresent(msg -> {
                    String url = msg.requestResponse().request() != null ? msg.requestResponse().request().url() : null;
                    if (url != null && !url.isEmpty()) {
                        settings.addGlobalIgnoredSource(url);
                        try { settings.saveGlobalIgnoredSourcesToGlobalDir(); } catch (Throwable ignored) {}
                        SwingUtilities.invokeLater(tab::refreshSettingsFromModel);
                    }
                }));

                return List.of(sendItem, ignoreItem);
            } catch (Throwable t) {
                log.logToError("Context menu error: " + t.getMessage());
                return List.of();
            }
        }
    }

    // Lightweight wrapper to adapt plain HttpResponse/Request to HttpResponseReceived for reuse
    private static class HttpResponseReceivedWrapper implements HttpResponseReceived {
        private final burp.api.montoya.http.message.responses.HttpResponse response;
        private final burp.api.montoya.http.message.requests.HttpRequest request;

        HttpResponseReceivedWrapper(burp.api.montoya.http.message.responses.HttpResponse res,
                                    burp.api.montoya.http.message.requests.HttpRequest req) {
            this.response = res;
            this.request = req;
        }

        @Override
        public int messageId() { return -1; }
        @Override
        public burp.api.montoya.http.message.requests.HttpRequest initiatingRequest() { return request; }
        @Override
        public burp.api.montoya.core.Annotations annotations() { return null; }
        @Override
        public burp.api.montoya.core.ToolSource toolSource() { return null; }
        @Override
        public short statusCode() { return response.statusCode(); }
        @Override
        public String reasonPhrase() { return response.reasonPhrase(); }
        @Override
        public boolean isStatusCodeClass(burp.api.montoya.http.message.StatusCodeClass c) { return response.isStatusCodeClass(c); }
        @Override
        public String httpVersion() { return response.httpVersion(); }
        @Override
        public java.util.List<burp.api.montoya.http.message.HttpHeader> headers() { return response.headers(); }
        @Override
        public boolean hasHeader(burp.api.montoya.http.message.HttpHeader h) { return response.hasHeader(h); }
        @Override
        public boolean hasHeader(String n) { return response.hasHeader(n); }
        @Override
        public boolean hasHeader(String n, String v) { return response.hasHeader(n, v); }
        @Override
        public burp.api.montoya.http.message.HttpHeader header(String n) { return response.header(n); }
        @Override
        public String headerValue(String n) { return response.headerValue(n); }
        @Override
        public burp.api.montoya.core.ByteArray body() { return response.body(); }
        @Override
        public String bodyToString() { return response.bodyToString(); }
        @Override
        public int bodyOffset() { return response.bodyOffset(); }
        @Override
        public java.util.List<burp.api.montoya.core.Marker> markers() { return response.markers(); }
        @Override
        public java.util.List<burp.api.montoya.http.message.Cookie> cookies() { return response.cookies(); }
        @Override
        public burp.api.montoya.http.message.Cookie cookie(String name) { return response.cookie(name); }
        @Override
        public String cookieValue(String name) { return response.cookieValue(name); }
        @Override
        public boolean hasCookie(String name) { return response.hasCookie(name); }
        @Override
        public boolean hasCookie(burp.api.montoya.http.message.Cookie c) { return response.hasCookie(c); }
        @Override
        public MimeType mimeType() { return response.mimeType(); }
        @Override
        public MimeType statedMimeType() { return response.statedMimeType(); }
        @Override
        public MimeType inferredMimeType() { return response.inferredMimeType(); }
        @Override
        public java.util.List<burp.api.montoya.http.message.responses.analysis.KeywordCount> keywordCounts(String... keys) { return response.keywordCounts(keys); }
        @Override
        public java.util.List<burp.api.montoya.http.message.responses.analysis.Attribute> attributes(burp.api.montoya.http.message.responses.analysis.AttributeType... t) { return response.attributes(t); }
        @Override
        public boolean contains(String s, boolean b) { return response.contains(s, b); }
        @Override
        public boolean contains(java.util.regex.Pattern p) { return response.contains(p); }
        @Override
        public burp.api.montoya.core.ByteArray toByteArray() { return response.toByteArray(); }
        @Override
        public String toString() { return response.toString(); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withStatusCode(short s) { return response.withStatusCode(s); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withReasonPhrase(String s) { return response.withReasonPhrase(s); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withHttpVersion(String s) { return response.withHttpVersion(s); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withBody(String s) { return response.withBody(s); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withBody(burp.api.montoya.core.ByteArray b) { return response.withBody(b); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withAddedHeader(burp.api.montoya.http.message.HttpHeader h) { return response.withAddedHeader(h); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withAddedHeader(String n, String v) { return response.withAddedHeader(n, v); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withAddedHeaders(java.util.List<? extends burp.api.montoya.http.message.HttpHeader> headers) { return response.withAddedHeaders(headers); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withAddedHeaders(burp.api.montoya.http.message.HttpHeader... headers) { return response.withAddedHeaders(headers); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withUpdatedHeader(burp.api.montoya.http.message.HttpHeader h) { return response.withUpdatedHeader(h); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withUpdatedHeader(String n, String v) { return response.withUpdatedHeader(n, v); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withUpdatedHeaders(java.util.List<? extends burp.api.montoya.http.message.HttpHeader> headers) { return response.withUpdatedHeaders(headers); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withUpdatedHeaders(burp.api.montoya.http.message.HttpHeader... headers) { return response.withUpdatedHeaders(headers); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withRemovedHeader(burp.api.montoya.http.message.HttpHeader h) { return response.withRemovedHeader(h); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withRemovedHeader(String n) { return response.withRemovedHeader(n); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withRemovedHeaders(java.util.List<? extends burp.api.montoya.http.message.HttpHeader> headers) { return response.withRemovedHeaders(headers); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withRemovedHeaders(burp.api.montoya.http.message.HttpHeader... headers) { return response.withRemovedHeaders(headers); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withMarkers(java.util.List<burp.api.montoya.core.Marker> m) { return response.withMarkers(m); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse withMarkers(burp.api.montoya.core.Marker... m) { return response.withMarkers(m); }
        @Override
        public burp.api.montoya.http.message.responses.HttpResponse copyToTempFile() { return response.copyToTempFile(); }
    }
}
