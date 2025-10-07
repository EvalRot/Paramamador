package burp.paramamador.datastore;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.stream.Collectors.toList;

/**
 * Thread-safe in-memory store with JSON persistence.
 */
public class DataStore {
    private final Map<String, ParameterRecord> parameters = new ConcurrentHashMap<>();
    private final Map<String, EndpointRecord> endpoints = new ConcurrentHashMap<>();

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Type PARAM_MAP_TYPE = new TypeToken<Map<String, ParameterRecord>>(){}.getType();
    private static final Type ENDPOINT_MAP_TYPE = new TypeToken<Map<String, EndpointRecord>>(){}.getType();

    public Map<String, ParameterRecord> parameters() { return parameters; }
    public Map<String, EndpointRecord> endpoints() { return endpoints; }

    // Parameters
    public void addOrUpdateParam(String name, String source, String type, String example) {
        if (name == null || name.isBlank()) return;
        ParameterRecord r = parameters.computeIfAbsent(name, ParameterRecord::new);
        r.sources.add(source);
        if (type != null) r.types.add(type);
        if (example != null) r.addExample(example);
        r.touch();
    }

    public void markOnlyInCode(String name, String pattern) {
        ParameterRecord r = parameters.computeIfAbsent(name, ParameterRecord::new);
        r.onlyInCode = true;
        if (pattern != null && !pattern.isBlank()) r.patternsFromJs.add(pattern);
    }

    // Endpoints
    public void addOrUpdateEndpoint(String endpoint, EndpointRecord.Type type, boolean inScope, String source, String context, String pattern, boolean notSure) {
        if (endpoint == null || endpoint.isBlank()) return;
        String key = endpointKey(endpoint, source);
        EndpointRecord e = endpoints.computeIfAbsent(key, k -> new EndpointRecord(endpoint, source, type, inScope, context, pattern));
        e.inScope = e.inScope || inScope;
        if (context != null && (e.contextSnippet == null || e.contextSnippet.isBlank())) e.contextSnippet = context;
        if (pattern != null && (e.pattern == null || e.pattern.isBlank())) e.pattern = pattern;
        e.notSure = e.notSure || notSure;
    }

    public void markEndpointFalsePositive(String endpoint, String source, boolean value) {
        if (endpoint == null) return;
        EndpointRecord e = endpoints.get(endpointKey(endpoint, source));
        if (e != null) e.falsePositive = value;
    }

    public List<ParameterRecord> snapshotParameters() {
        return parameters.values().stream().sorted(Comparator.comparing(r -> r.name)).collect(toList());
    }

    public List<EndpointRecord> snapshotEndpoints() {
        return endpoints.values().stream()
                .filter(e -> !e.notSure && !e.falsePositive)
                .sorted(Comparator.comparing(e -> e.endpointString))
                .collect(toList());
    }

    public List<EndpointRecord> snapshotNotSureEndpoints() {
        return endpoints.values().stream()
                .filter(e -> e.notSure && !e.falsePositive)
                .sorted(Comparator.comparing(ep -> ep.endpointString))
                .collect(toList());
    }

    private static String endpointKey(String endpoint, String source) {
        String s = source == null ? "" : source;
        return s + "||" + endpoint;
    }

    public void saveToDisk(Path parametersFile, Path endpointsFile) throws IOException {
        if (parametersFile != null) {
            java.nio.file.Files.createDirectories(parametersFile.getParent());
            java.nio.file.Files.writeString(parametersFile, GSON.toJson(parameters, PARAM_MAP_TYPE));
        }
        if (endpointsFile != null) {
            java.nio.file.Files.createDirectories(endpointsFile.getParent());
            java.nio.file.Files.writeString(endpointsFile, GSON.toJson(endpoints, ENDPOINT_MAP_TYPE));
        }
    }

    public void loadFromFiles(java.util.List<Path> files) throws IOException {
        if (files == null || files.isEmpty()) return;
        for (Path f : files) {
            if (f == null) continue;
            if (!Files.isRegularFile(f)) continue;
            String json = Files.readString(f);
            if (json == null || json.isBlank()) continue;
            // Try endpoints first
            Map<String, EndpointRecord> eMap = null;
            try {
                eMap = GSON.fromJson(json, ENDPOINT_MAP_TYPE);
            } catch (Throwable ignored) {}
            boolean endpointsDetected = false;
            if (eMap != null && !eMap.isEmpty()) {
                for (EndpointRecord v : eMap.values()) {
                    if (v != null && v.endpointString != null) { endpointsDetected = true; break; }
                }
            }
            if (endpointsDetected) {
                for (Map.Entry<String, EndpointRecord> en : eMap.entrySet()) {
                    EndpointRecord rec = en.getValue();
                    if (rec == null) continue;
                    String src = rec.source;
                    String ep = rec.endpointString;
                    if ((src == null || src.isBlank() || ep == null || ep.isBlank()) && en.getKey() != null) {
                        String k = en.getKey();
                        int sep = k.indexOf("||");
                        if (sep >= 0 && sep + 2 < k.length()) {
                            if (src == null || src.isBlank()) src = k.substring(0, sep);
                            if (ep == null || ep.isBlank()) ep = k.substring(sep + 2);
                        }
                    }
                    if (ep == null || ep.isBlank()) continue;
                    addOrUpdateEndpoint(ep, rec.type, rec.inScope, src, rec.contextSnippet, rec.pattern, rec.notSure);
                    if (rec.falsePositive) {
                        markEndpointFalsePositive(ep, src, true);
                    }
                }
                continue;
            }

            // Try parameters
            Map<String, ParameterRecord> pMap = null;
            try {
                pMap = GSON.fromJson(json, PARAM_MAP_TYPE);
            } catch (Throwable ignored) {}
            boolean paramsDetected = false;
            if (pMap != null && !pMap.isEmpty()) {
                for (ParameterRecord v : pMap.values()) {
                    if (v != null && v.name != null) { paramsDetected = true; break; }
                }
            }
            if (paramsDetected) {
                for (Map.Entry<String, ParameterRecord> en : pMap.entrySet()) {
                    ParameterRecord incoming = en.getValue();
                    if (incoming == null) continue;
                    String name = incoming.name != null ? incoming.name : en.getKey();
                    if (name == null || name.isBlank()) continue;
                    ParameterRecord r = parameters.computeIfAbsent(name, ParameterRecord::new);
                    // merge sets
                    if (incoming.sources != null) r.sources.addAll(incoming.sources);
                    if (incoming.types != null) r.types.addAll(incoming.types);
                    if (incoming.patternsFromJs != null) r.patternsFromJs.addAll(incoming.patternsFromJs);
                    // merge examples (respect size cap in addExample)
                    if (incoming.exampleValues != null) {
                        for (String ex : incoming.exampleValues) r.addExample(ex);
                    }
                    // merge counters and timestamps
                    r.count += Math.max(0, incoming.count);
                    if (incoming.firstSeen > 0) r.firstSeen = r.firstSeen == 0 ? incoming.firstSeen : Math.min(r.firstSeen, incoming.firstSeen);
                    if (incoming.lastSeen > 0) r.lastSeen = Math.max(r.lastSeen, incoming.lastSeen);
                    r.onlyInCode = r.onlyInCode || incoming.onlyInCode;
                }
            }
        }
    }

    public void clearAll() {
        parameters.clear();
        endpoints.clear();
    }
}
