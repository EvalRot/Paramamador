package burp.paramamador.analyzer;

import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.logging.Logging;
import burp.paramamador.Settings;
import burp.paramamador.datastore.DataStore;
import burp.paramamador.util.JsonUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/**
 * Fast, inline parameter extraction. Keeps work light to avoid blocking.
 */
public class ParameterAnalyzer {
    private final DataStore store;
    private final Settings settings;
    private final Logging log;

    public ParameterAnalyzer(DataStore store, Settings settings, Logging log) {
        this.store = store;
        this.settings = settings;
        this.log = log;
    }

    public void extractFromRequest(HttpRequestToBeSent request) {
        if (request == null) return;
        String host = safeHost(request.url());
        String source = host + " " + request.path();

        // Query and body parameters via Montoya parsed params
        for (ParsedHttpParameter p : request.parameters(HttpParameterType.URL)) {
            store.addOrUpdateParam(p.name(), source, "query", p.value());
        }
        for (ParsedHttpParameter p : request.parameters(HttpParameterType.BODY)) {
            store.addOrUpdateParam(p.name(), source, "body", p.value());
        }
        for (ParsedHttpParameter p : request.parameters(HttpParameterType.MULTIPART_ATTRIBUTE)) {
            store.addOrUpdateParam(p.name(), source, "multipart", p.value());
        }
        if (request.contentType() == ContentType.JSON) {
            Set<String> keys = JsonUtils.collectJsonKeys(request.bodyToString());
            for (String k : keys) store.addOrUpdateParam(k, source, "json", null);
        }

        // Cookie names from request (Cookie header)
        String cookieHeader = request.headerValue("Cookie");
        if (cookieHeader != null) {
            for (String pair : cookieHeader.split(";")) {
                String name = pair.trim();
                int eq = name.indexOf('=');
                if (eq > 0) name = name.substring(0, eq);
                if (!name.isBlank()) store.addOrUpdateParam(name, source, "cookie", null);
            }
        }
    }

    public void extractFromResponse(burp.api.montoya.http.message.requests.HttpRequest initiatingRequest,
                                    HttpResponseReceived response) {
        if (response == null) return;
        String reqUrl = initiatingRequest != null ? initiatingRequest.url() : "";
        String host = safeHost(reqUrl);
        String source = host + " " + (initiatingRequest != null ? initiatingRequest.path() : "");

        // Cookies set by response (Set-Cookie header) -> names only
        response.cookies().forEach(c -> store.addOrUpdateParam(c.name(), source, "cookie", null));

        // JSON keys in body (if likely JSON)
        boolean jsonByMime = response.mimeType() == burp.api.montoya.http.message.MimeType.JSON;
        boolean jsonByHeader = Optional.ofNullable(response.headerValue("Content-Type")).map(String::toLowerCase).orElse("").contains("application/json");
        if (jsonByMime || jsonByHeader) {
            Set<String> keys = JsonUtils.collectJsonKeys(response.bodyToString());
            for (String k : keys) store.addOrUpdateParam(k, source, "json", null);
        }
    }

    private static String safeHost(String url) {
        try { return new URI(url == null ? "" : url).getHost(); } catch (URISyntaxException e) { return ""; }
    }
}

