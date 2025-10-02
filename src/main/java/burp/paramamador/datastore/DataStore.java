package burp.paramamador.datastore;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Path;
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

    public void markOnlyInCode(String name) {
        ParameterRecord r = parameters.computeIfAbsent(name, ParameterRecord::new);
        r.onlyInCode = true;
    }

    // Endpoints
    public void addOrUpdateEndpoint(String endpoint, EndpointRecord.Type type, boolean inScope, String source, String context) {
        if (endpoint == null || endpoint.isBlank()) return;
        EndpointRecord e = endpoints.computeIfAbsent(endpoint, k -> new EndpointRecord(endpoint, type, inScope, context));
        if (source != null) e.sources.add(source);
        e.inScope = e.inScope || inScope;
        if (context != null && (e.contextSnippet == null || e.contextSnippet.isBlank())) e.contextSnippet = context;
    }

    public List<ParameterRecord> snapshotParameters() {
        return parameters.values().stream().sorted(Comparator.comparing(r -> r.name)).collect(toList());
    }

    public List<EndpointRecord> snapshotEndpoints() {
        return endpoints.values().stream().sorted(Comparator.comparing(e -> e.endpointString)).collect(toList());
    }

    // Persistence
    public void saveToDisk(Path dir) throws IOException {
        java.nio.file.Files.writeString(dir.resolve("paramamador_parameters.json"), GSON.toJson(parameters, PARAM_MAP_TYPE));
        java.nio.file.Files.writeString(dir.resolve("paramamador_endpoints.json"), GSON.toJson(endpoints, ENDPOINT_MAP_TYPE));
    }

    public void clearAll() {
        parameters.clear();
        endpoints.clear();
    }
}
