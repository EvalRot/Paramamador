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

import javax.swing.*;
import java.awt.*;
import java.time.Instant;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

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

    private final LinkedBlockingQueue<JsTask> jsQueue = new LinkedBlockingQueue<>(settings.getMaxQueueSize());
    private ExecutorService jsExecutor;
    private ScheduledExecutorService scheduler;

    private Registration httpHandlerReg;
    private Registration suiteTabReg;
    private Registration settingsPanelReg;
    private Registration contextMenuReg;
    private Registration unloadReg;

    private ParamamadorTab tab;
    private SiteTreeScanner siteTreeScanner;

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

        // Prepare worker executors
        this.jsExecutor = Executors.newFixedThreadPool(settings.getWorkerThreads(), r -> {
            Thread t = new Thread(r, "paramamador-js-worker");
            t.setDaemon(true);
            return t;
        });
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

        // Start scheduled autosave
        scheduler.scheduleAtFixedRate(this::saveAllSafe, settings.getAutoSaveSeconds(), settings.getAutoSaveSeconds(), TimeUnit.SECONDS);

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
        }, this::saveAllSafe);
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
                                "Ignored patterns (comma-separated)",
                                String.join(",", settings.getIgnoredPatterns())
                        )
                )
                .build();
        this.settingsPanelReg = ui.registerSettingsPanel(settingsPanel);

        // Context menu items provider (simple integration)
        this.contextMenuReg = ui.registerContextMenuItemsProvider(new SimpleContextMenuProvider());

        // Site tree scanner depends on API + analyzers
        JsEndpointAnalyzer jsAnalyzer = new JsEndpointAnalyzer(store, settings, scope, log);
        this.siteTreeScanner = new SiteTreeScanner(api, jsAnalyzer, settings, store, log);

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

    private void shutdown() {
        saveAllSafe();
        if (httpHandlerReg != null) httpHandlerReg.deregister();
        if (suiteTabReg != null) suiteTabReg.deregister();
        if (settingsPanelReg != null) settingsPanelReg.deregister();
        if (contextMenuReg != null) contextMenuReg.deregister();
        if (unloadReg != null) unloadReg.deregister();
        if (scheduler != null) scheduler.shutdownNow();
        if (jsExecutor != null) jsExecutor.shutdownNow();
        log.logToOutput("Paramamador unloaded");
    }

    private void saveAllSafe() {
        try {
            IOUtils.ensureDir(settings.getExportDir());
            store.saveToDisk(settings.getExportDir());
        } catch (Throwable t) {
            log.logToError("Save failed: " + t.getMessage());
        }
    }

    private void createStartupSnapshots() {
        try {
            IOUtils.ensureDir(settings.getExportDir());
        } catch (java.io.IOException ioe) {
            throw new RuntimeException(ioe);
        }
        String base = settings.getSnapshotNamePrefix();
        if (base == null || base.isBlank()) base = safeProjectName();
        String ts = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        java.nio.file.Path params = settings.getExportDir().resolve("paramamador_" + base + "_" + ts + "_parameters.json");
        java.nio.file.Path endpoints = settings.getExportDir().resolve("paramamador_" + base + "_" + ts + "_endpoints.json");
        try {
            store.saveToDisk(params, endpoints);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void showInitialSetupDialog() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            try {
                JTextField nameField = new JTextField();
                String suggested = safeProjectName();
                if (settings.getSnapshotNamePrefix() != null && !settings.getSnapshotNamePrefix().isBlank()) {
                    suggested = settings.getSnapshotNamePrefix();
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

                JPanel panel = new JPanel(new GridBagLayout());
                GridBagConstraints c = new GridBagConstraints();
                c.insets = new Insets(4,4,4,4);
                c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1;
                int row = 0;
                c.gridx = 0; c.gridy = row; panel.add(new JLabel("Filename base"), c);
                c.gridx = 1; panel.add(nameField, c); row++;
                c.gridx = 0; c.gridy = row; panel.add(new JLabel("Export directory"), c);
                JPanel dirPanel = new JPanel(new BorderLayout());
                dirPanel.add(dirField, BorderLayout.CENTER);
                dirPanel.add(browse, BorderLayout.EAST);
                c.gridx = 1; panel.add(dirPanel, c); row++;

                int option = JOptionPane.showConfirmDialog(null, panel, "Paramamador Setup", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
                if (option == JOptionPane.OK_OPTION) {
                    String baseName = nameField.getText();
                    if (baseName != null && !baseName.isBlank()) settings.setSnapshotNamePrefix(baseName.trim());
                    String dir = dirField.getText();
                    if (dir != null && !dir.isBlank()) settings.setExportDir(java.nio.file.Paths.get(dir.trim()));
                }
            } catch (Throwable t) {
                log.logToError("Setup dialog error: " + t.getMessage());
            }
        });
    }

    private String safeProjectName() {
        // 1) Try a system property if present (no official Montoya API for project name)
        String name = null;
        try { name = System.getProperty("burp.project.name"); } catch (Throwable ignored) {}
        if (name != null && !name.isBlank()) {
            return name.replaceAll("[^A-Za-z0-9_-]", "_");
        }

        // 2) Use first in-scope domain from Site Map
        try {
            if (siteMap != null && scope != null) {
                for (var rr : siteMap.requestResponses()) {
                    try {
                        var req = rr.request();
                        if (req == null) continue;
                        String url = req.url();
                        if (url == null || url.isBlank()) continue;
                        if (!scope.isInScope(url)) continue;
                        try {
                            java.net.URI uri = java.net.URI.create(url);
                            String host = uri.getHost();
                            if (host != null && !host.isBlank()) {
                                return host.replaceAll("[^A-Za-z0-9._-]", "_");
                            }
                        } catch (Throwable ignored) {}
                    } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable ignored) {}

        // 3) Fallback
        return "burp";
    }

    

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
                String referer = response.initiatingRequest() != null ? response.initiatingRequest().headerValue("Referer") : null;
                String ct = response.headerValue("Content-Type");
                boolean looksLikeJs = response.mimeType() == MimeType.SCRIPT
                        || (ct != null && ct.toLowerCase().contains("javascript"))
                        || (url != null && url.toLowerCase().endsWith(".js"));

                if (looksLikeJs) {
                    String body = response.bodyToString();
                    int sizeKb = body != null ? body.length() / 1024 : 0;
                    boolean inScope = response.initiatingRequest() != null && response.initiatingRequest().isInScope();

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

                JMenuItem ignoreItem = new JMenuItem("Paramamador: Ignore this JS");
                ignoreItem.addActionListener(a -> event.messageEditorRequestResponse().ifPresent(msg -> {
                    String url = msg.requestResponse().request() != null ? msg.requestResponse().request().url() : null;
                    if (url != null && !url.isEmpty()) {
                        settings.addIgnoredPattern(url);
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
