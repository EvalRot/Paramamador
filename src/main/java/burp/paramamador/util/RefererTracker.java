package burp.paramamador.util;

import burp.paramamador.Settings;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks mapping from JS source URL -> Referer URL (last seen),
 * and provides convenient host options (referer host and JS host)
 * with scheme detection for use in Send-to-Repeater UI.
 */
public final class RefererTracker {
    private static final ConcurrentHashMap<String, String> JS_TO_REFERER_URL = new ConcurrentHashMap<>();
    private static final Object FILE_LOCK = new Object();
    private static volatile Path persistentFile;
    private static final java.util.concurrent.ConcurrentSkipListSet<String> USER_HOSTS = new java.util.concurrent.ConcurrentSkipListSet<>(String.CASE_INSENSITIVE_ORDER);
    private static volatile Path userHostsFile;

    private RefererTracker() {}

    public static void init(Settings settings) {
        try {
            persistentFile = settings == null ? null : settings.jsReferersFilePath();
            userHostsFile = settings == null ? null : settings.globalUserHostsFilePath();
            if (persistentFile != null) {
                Files.createDirectories(persistentFile.getParent());
            }
            if (persistentFile != null && Files.isRegularFile(persistentFile)) {
                List<String> lines = Files.readAllLines(persistentFile, StandardCharsets.UTF_8);
                for (String line : lines) {
                    if (line == null) continue;
                    String t = line.trim();
                    if (t.isEmpty()) continue;
                    int tab = t.indexOf('\t');
                    if (tab <= 0) continue;
                    String jsUrl = t.substring(0, tab);
                    String ref = t.substring(tab + 1).trim();
                    if (!jsUrl.isEmpty() && !ref.isEmpty()) {
                        JS_TO_REFERER_URL.put(jsUrl, ref);
                    }
                }
            }
            // Load user hosts
            if (userHostsFile != null) {
                try {
                    Files.createDirectories(userHostsFile.getParent());
                    if (Files.isRegularFile(userHostsFile)) {
                        List<String> hosts = Files.readAllLines(userHostsFile, StandardCharsets.UTF_8);
                        for (String h : hosts) {
                            if (h == null) continue;
                            String t = h.trim();
                            if (!t.isEmpty()) USER_HOSTS.add(t);
                        }
                    }
                } catch (Throwable ignored) {}
            }
        } catch (Throwable ignored) {}
    }

    public static void record(String jsUrl, String refererUrl) {
        if (jsUrl == null || jsUrl.isBlank()) return;
        if (refererUrl == null || refererUrl.isBlank()) return;
        JS_TO_REFERER_URL.put(jsUrl, refererUrl);
        Path f = persistentFile;
        if (f != null) {
            try {
                String line = jsUrl + "\t" + refererUrl + System.lineSeparator();
                synchronized (FILE_LOCK) {
                    Files.writeString(f, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                }
            } catch (Throwable ignored) {}
        }
    }

    public static String getRefererUrl(String jsUrl) {
        if (jsUrl == null) return null;
        return JS_TO_REFERER_URL.get(jsUrl);
    }

    public static HostOption refererOption(String jsUrl) {
        String ref = getRefererUrl(jsUrl);
        return parseHostOption(ref);
    }

    public static HostOption jsOption(String jsUrl) {
        return parseHostOption(jsUrl);
    }

    public static HostOption parseHostOption(String url) {
        if (url == null || url.isBlank()) return null;
        try {
            URI u = URI.create(url);
            String host = u.getHost();
            if (host == null || host.isBlank()) return null;
            boolean secure = false;
            String scheme = u.getScheme();
            if (scheme != null) {
                secure = scheme.toLowerCase(Locale.ROOT).startsWith("https");
            }
            int port = u.getPort(); // -1 if not set
            return new HostOption(hostWithPort(host, port), secure);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String hostWithPort(String host, int port) {
        if (port <= 0) return host;
        return host + ":" + port;
    }

    public static HostOption fromUserInput(String input, HostOption defaultSecureHint) {
        if (input == null) return null;
        String s = input.trim();
        if (s.isEmpty()) return null;
        boolean secure = defaultSecureHint != null && defaultSecureHint.secure();
        String host = s;
        try {
            if (s.toLowerCase(Locale.ROOT).startsWith("http://") || s.toLowerCase(Locale.ROOT).startsWith("https://")) {
                URI u = URI.create(s);
                secure = (u.getScheme() != null && u.getScheme().toLowerCase(Locale.ROOT).startsWith("https"));
                String h = u.getHost();
                if (h != null && !h.isBlank()) {
                    host = hostWithPort(h, u.getPort());
                }
            }
        } catch (Throwable ignored) {}
        return new HostOption(host, secure);
    }

    public static java.util.List<String> userHosts() {
        return new java.util.ArrayList<>(USER_HOSTS);
    }

    public static void addUserHost(String host) {
        if (host == null) return;
        String h = host.trim();
        if (h.isEmpty()) return;
        boolean added = USER_HOSTS.add(h);
        if (added && userHostsFile != null) {
            try {
                synchronized (FILE_LOCK) {
                    Files.writeString(userHostsFile, h + System.lineSeparator(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                }
            } catch (Throwable ignored) {}
        }
    }

    public static record HostOption(String host, boolean secure) {
        public String displayLabel() { return host == null ? "" : host; }
        public boolean isValid() { return host != null && !host.isBlank(); }
    }
}
