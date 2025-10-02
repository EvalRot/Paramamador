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
    // RFC 3986 path characters: unreserved / pct-encoded / sub-delims / ":" / "@" and "/" as segment separator.
    // Allow optional query ("?" + [pchar|"/"|"?"]*) to preserve downstream query param extraction.
    private static final Pattern ABS_PATH = Pattern.compile(
            "(?:\\\"|')"
            + "(/(?:(?:%[0-9A-Fa-f]{2})|[A-Za-z0-9\\-\\._~!\\$&'\\(\\)\\*\\+,;=:@/])+)(?:\\?(?:(?:%[0-9A-Fa-f]{2})|[A-Za-z0-9\\-\\._~!\\$&'\\(\\)\\*\\+,;=:@/?])*)?"
            + "(?:\\\"|')"
    );
    private static final Pattern REL_PATH = Pattern.compile(
            "(?:\\\"|')"
            + "(?=[^\\\"']*/)" // require at least one slash inside the literal
            + "((?!/)(?:(?:%[0-9A-Fa-f]{2})|[A-Za-z0-9\\-\\._~!\\$&'\\(\\)\\*\\+,;=:@])(?:(?:%[0-9A-Fa-f]{2})|[A-Za-z0-9\\-\\._~!\\$&'\\(\\)\\*\\+,;=:@/])*)(?:\\?(?:(?:%[0-9A-Fa-f]{2})|[A-Za-z0-9\\-\\._~!\\$&'\\(\\)\\*\\+,;=:@/?])*)?"
            + "(?:\\\"|')"
    );
    private static final Pattern TEMPLATE = Pattern.compile("`([^`]+)`");
    // Require a slash AND at least one alphanumeric in the string literal to reduce noise
    private static final Pattern CONCAT_A = Pattern.compile("\"(?=[^\\\"]*/)(?=[^\\\"]*[A-Za-z0-9])([^\\\"]*)\"\\s*\\+\\s*([A-Za-z0-9_\\$\\.]+)");
    private static final Pattern CONCAT_B = Pattern.compile("([A-Za-z0-9_\\$\\.]+)\\s*\\+\\s*\"(?=[^\\\"]*/)(?=[^\\\"]*[A-Za-z0-9])([^\\\"]*)\"");

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
            addEndpoint(url, EndpointRecord.Type.ABSOLUTE, inScope, sourceUrl, context(js, m.start(), m.end()), FULL_URL.pattern(), false);
        }

        // Absolute paths
        m = ABS_PATH.matcher(js);
        while (m.find()) {
            String path = m.group(1);
            boolean inScope = inScopeHint || isRefererInScope(referer);
            addEndpoint(path, EndpointRecord.Type.RELATIVE, inScope, sourceUrl, context(js, m.start(1), m.end(1)), ABS_PATH.pattern(), false);
        }

        // Relative paths
        m = REL_PATH.matcher(js);
        while (m.find()) {
            String path = m.group(1);
            boolean inScope = inScopeHint || isRefererInScope(referer);
            addEndpoint(path, EndpointRecord.Type.RELATIVE, inScope, sourceUrl, context(js, m.start(1), m.end(1)), REL_PATH.pattern(), false);
        }

        // Template literals: replace ${...} with EXPR
        m = TEMPLATE.matcher(js);
        while (m.find()) {
            String tpl = m.group(1);
            String masked = tpl.replaceAll("\\$\\{[^}]+}", "EXPR");
            // Look for urls/paths inside
            Matcher innerUrl = FULL_URL.matcher(masked);
            while (innerUrl.find()) {
                // Provide original (unmasked) template content as context snippet
                addEndpoint(innerUrl.group(1), EndpointRecord.Type.TEMPLATE, inScopeHint || isRefererInScope(referer), sourceUrl,
                        tpl, FULL_URL.pattern(), false);
            }
            if (masked.startsWith("/")) {
                // Provide original (unmasked) template content as context snippet
                addEndpoint(masked, EndpointRecord.Type.TEMPLATE, inScopeHint || isRefererInScope(referer), sourceUrl,
                        tpl, TEMPLATE.pattern(), false);
            }
        }

        // Simple string concatenations "a" + var and var + "b"
        for (Pattern p : List.of(CONCAT_A, CONCAT_B)) {
            m = p.matcher(js);
            while (m.find()) {
                String candidate;
                boolean suspiciousLiteral = false;
                if (p == CONCAT_A) {
                    String left = m.group(1);      // string literal content
                    String var = m.group(2);       // variable/expression token
                    candidate = left + var;        // keep variable name as-is (no EXPR masking)
                    // If the literal part contains any of () $ ' + , @ ~ < > & = then mark as not-sure
                    if (left != null && left.matches(".*[\u0028\u0029\u0024\u0027\u002B\u002C\u0040\u007E\u003C\u003E\u0026\u003D].*")) suspiciousLiteral = true;
                } else { // CONCAT_B
                    String var = m.group(1);       // variable/expression token
                    String right = m.group(2);     // string literal content
                    candidate = var + right;       // keep variable name as-is (no EXPR masking)
                    if (right != null && right.matches(".*[\u0028\u0029\u0024\u0027\u002B\u002C\u0040\u007E\u003C\u003E\u0026\u003D].*")) suspiciousLiteral = true;
                }
                if (!candidate.isBlank()) {
                    EndpointRecord.Type type = candidate.startsWith("/") ? EndpointRecord.Type.RELATIVE : EndpointRecord.Type.CONCAT;
                    addEndpoint(candidate, type, inScopeHint || isRefererInScope(referer), sourceUrl, context(js, m.start(), m.end()), p.pattern(), suspiciousLiteral);
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

    private void addEndpoint(String value, EndpointRecord.Type type, boolean inScope, String source, String ctx, String pattern, boolean extraNotSure) {
        boolean notSure = false;
        try {
            // Rule 1: for ABS_PATH/REL_PATH derived (type RELATIVE and pattern equals ABS_PATH|REL_PATH),
            // if path contains any of: () $ ' + , @ ~ < > & =
            boolean fromRelPatterns = type == EndpointRecord.Type.RELATIVE
                    && pattern != null
                    && (pattern.equals(ABS_PATH.pattern()) || pattern.equals(REL_PATH.pattern()));
            if (fromRelPatterns && value != null) {
                String pathOnly = value;
                int qpos = pathOnly.indexOf('?');
                if (qpos >= 0) pathOnly = pathOnly.substring(0, qpos);
                if (pathOnly.matches(".*[\u0028\u0029\u0024\u0027\u002B\u002C\u0040\u007E\u003C\u003E\u0026\u003D].*")) { // ( ) $ ' + , @ ~ < > & =
                    notSure = true;
                }
            }

            // Rule 2: endpoints with no alphanumeric characters at all
            if (value != null && !value.isEmpty() && !value.matches(".*[A-Za-z0-9].*")) {
                notSure = true;
            }
            // Rule 3: suspicious literal in CONCAT patterns
            if (extraNotSure) {
                notSure = true;
            }
        } catch (Throwable ignored) {}

        store.addOrUpdateEndpoint(value, type, inScope, source, ctx, pattern, notSure);
        // Derive parameter names from query strings in the endpoint and mark them as only-in-code
        if (value != null) {
            int q = value.indexOf('?');
            if (q >= 0 && q + 1 < value.length()) {
                String qs = value.substring(q + 1);
                for (String part : qs.split("&")) {
                    int eq = part.indexOf('=');
                    String name = eq > 0 ? part.substring(0, eq) : part;
                    if (!name.isBlank()) {
                        store.markOnlyInCode(name, pattern);
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
