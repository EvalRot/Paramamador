package burp.paramamador.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.sitemap.SiteMap;
import burp.paramamador.Settings;
import burp.paramamador.analyzer.JsEndpointAnalyzer;
import burp.paramamador.datastore.DataStore;
import burp.paramamador.integrations.JsluiceService;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Scans Site Map for JavaScript URLs that haven't been analyzed via proxy,
 * fetches them using Burp's HTTP client and runs the same JS analysis.
 */
public class SiteTreeScanner {
    private final MontoyaApi api;
    private final JsEndpointAnalyzer jsAnalyzer;
    private final Settings settings;
    private final DataStore store;
    private final Logging log;
    private final JsluiceService jsluiceService;
    private final Set<String> processed = ConcurrentHashMap.newKeySet();

    public SiteTreeScanner(MontoyaApi api, JsEndpointAnalyzer jsAnalyzer, Settings settings, DataStore store, Logging log, JsluiceService jsluiceService) {
        this.api = api;
        this.jsAnalyzer = jsAnalyzer;
        this.settings = settings;
        this.store = store;
        this.log = log;
        this.jsluiceService = jsluiceService;
    }

    public void rescanSiteTree() {
        SiteMap siteMap = api.siteMap();
        Http http = api.http();
        int count = 0;
        for (HttpRequestResponse rr : siteMap.requestResponses()) {
            String url = rr.request().url();
            if (url == null) continue;
            String lower = url.toLowerCase();
            if (!lower.endsWith(".js")) continue;
            if (processed.contains(url)) continue;

            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                HttpRequestResponse fetched = http.sendRequest(req);
                if (fetched != null && fetched.response() != null) {
                    String body = fetched.response().bodyToString();
                    // Determine inScope using the original request if possible
                    boolean inScope = rr.request().isInScope();
                    String ref = rr.request().headerValue("Referer");
                    String org = rr.request().headerValue("Origin");
                    String referer = (ref != null && !ref.isBlank()) ? ref : org;
                    try {
                        if (jsluiceService != null && body != null && !body.isBlank()) {
                            jsluiceService.enqueue(url, referer, body, inScope);
                        }
                    } catch (Throwable ignored) {}
                    jsAnalyzer.extractEndpoints(url, referer, body, inScope);
                    processed.add(url);
                    count++;
                }
            } catch (Throwable t) {
                log.logToError("Rescan error for URL " + url + ": " + t.getMessage());
            }
        }
        log.logToOutput("Rescan complete. Analyzed JS files: " + count);
    }
}
