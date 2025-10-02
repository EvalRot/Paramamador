package burp.paramamador.analyzer;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.scope.Scope;
import burp.paramamador.Settings;
import burp.paramamador.datastore.DataStore;
import burp.paramamador.datastore.EndpointRecord;

import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Static JavaScript endpoint extraction inspired by LinkFinder.
 * Performs regex-based extraction, including full URLs, absolute/relative paths,
 * template literals and simple string concatenations. Variables / expressions are
 * replaced with EXPR to form a masked pattern.
 */
public class JsEndpointAnalyzer {

    private final DataStore store;
    private final Settings settings;
    private final Scope scope;
    private final Logging log;

    private static final Pattern FULL_URL = Pattern.compile("(?i)(https?:\\/\\/[^\\s\"'\\\\<>]+)");
    private static final Pattern ABS_PATH = Pattern.compile("(?:\"|')(/[^\\s\"'\\\\<>]+)(?:\"|')");
    private static final Pattern REL_PATH = Pattern.compile("(?:\"|')(?:\\.\\./|\\./|[A-Za-z0-9_\\-/])([^\"'\\\\<>]*)(?:\"|')");
    private static final Pattern TEMPLATE = Pattern.compile("`([^`]+)`");
    private static final Pattern CONCAT_A = Pattern.compile("\"(.*?)\"\\s*\\+\\s*([A-Za-z0-9_\\$\\.]+)");
    private static final Pattern CONCAT_B = Pattern.compile("([A-Za-z0-9_\\$\\.]+)\\s*\\+\\s*\"(.*?)\"");

    public JsEndpointAnalyzer(DataStore store, Settings settings, Scope scope, Logging log) {
        this.store = store;
        this.settings = settings;
        this.scope = scope;
        this.log = log;
    }

    public void extractEndpoints(String sourceUrl, String referer, String js, boolean inScopeHint) {
        if (js == null || js.isBlank()) return;
        if (shouldIgnore(sourceUrl)) return;

        // Full URLs
        Matcher m = FULL_URL.matcher(js);
        while (m.find()) {
            String url = m.group(1);
            boolean inScope = inScopeHint || isInScope(url) || isRefererInScope(referer);
            addEndpoint(url, EndpointRecord.Type.ABSOLUTE, inScope, sourceUrl, context(js, m.start(), m.end()));
        }

        // Absolute paths
        m = ABS_PATH.matcher(js);
        while (m.find()) {
            String path = m.group(1);
            boolean inScope = inScopeHint || isRefererInScope(referer);
            addEndpoint(path, EndpointRecord.Type.RELATIVE, inScope, sourceUrl, context(js, m.start(1), m.end(1)));
        }

        // Relative paths
        m = REL_PATH.matcher(js);
        while (m.find()) {
            String path = m.group(0).replace("\"", "").replace("'", "");
            boolean inScope = inScopeHint || isRefererInScope(referer);
            addEndpoint(path, EndpointRecord.Type.RELATIVE, inScope, sourceUrl, context(js, m.start(), m.end()));
        }

        // Template literals: replace ${...} with EXPR
        m = TEMPLATE.matcher(js);
        while (m.find()) {
            String tpl = m.group(1);
            String masked = tpl.replaceAll("\\$\\{[^}]+}", "EXPR");
            // Look for urls/paths inside
            Matcher innerUrl = FULL_URL.matcher(masked);
            while (innerUrl.find()) {
                addEndpoint(innerUrl.group(1), EndpointRecord.Type.TEMPLATE, inScopeHint || isRefererInScope(referer), sourceUrl,
                        context(masked, innerUrl.start(1), innerUrl.end(1)));
            }
            if (masked.startsWith("/")) {
                addEndpoint(masked, EndpointRecord.Type.TEMPLATE, inScopeHint || isRefererInScope(referer), sourceUrl,
                        context(masked, 0, masked.length()));
            }
        }

        // Simple string concatenations "a" + var and var + "b"
        for (Pattern p : List.of(CONCAT_A, CONCAT_B)) {
            m = p.matcher(js);
            while (m.find()) {
                String left = m.group(1);
                String right = m.groupCount() >= 2 ? m.group(2) : "";
                String candidate = (p == CONCAT_A ? left + "EXPR" : "EXPR" + right);
                if (!candidate.isBlank()) {
                    EndpointRecord.Type type = candidate.startsWith("/") ? EndpointRecord.Type.RELATIVE : EndpointRecord.Type.TEMPLATE;
                    addEndpoint(candidate, type, inScopeHint || isRefererInScope(referer), sourceUrl, context(js, m.start(), m.end()));
                }
            }
        }
    }

    private boolean shouldIgnore(String urlOrName) {
        if (urlOrName == null) return false;
        String l = urlOrName.toLowerCase(Locale.ROOT);
        for (String pat : settings.getIgnoredPatterns()) {
            if (l.contains(pat.toLowerCase(Locale.ROOT))) return true;
        }
        return false;
    }

    private boolean isRefererInScope(String referer) {
        if (referer == null || referer.isBlank()) return false;
        try {
            return scope.isInScope(referer);
        } catch (Throwable t) {
            return false;
        }
    }

    private boolean isInScope(String url) {
        try {
            return scope.isInScope(url);
        } catch (Throwable t) {
            return false;
        }
    }

    private void addEndpoint(String value, EndpointRecord.Type type, boolean inScope, String source, String ctx) {
        store.addOrUpdateEndpoint(value, type, inScope, source, ctx);
        // Derive parameter names from query strings in the endpoint and mark them as only-in-code
        if (value != null) {
            int q = value.indexOf('?');
            if (q >= 0 && q + 1 < value.length()) {
                String qs = value.substring(q + 1);
                for (String part : qs.split("&")) {
                    int eq = part.indexOf('=');
                    String name = eq > 0 ? part.substring(0, eq) : part;
                    if (!name.isBlank()) {
                        store.markOnlyInCode(name);
                    }
                }
            }
        }
    }

    private static String context(String s, int start, int end) {
        int from = Math.max(0, start - 40);
        int to = Math.min(s.length(), end + 40);
        return s.substring(from, to);
    }
}
