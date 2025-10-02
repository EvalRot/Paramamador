package burp.paramamador.util;

import com.google.gson.*;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class JsonUtils {
    private JsonUtils() {}

    private static final JsonParser PARSER = new JsonParser();

    /** Recursively collect all JSON keys present in the element. */
    public static Set<String> collectJsonKeys(String json) {
        Set<String> keys = new HashSet<>();
        if (json == null || json.isBlank()) return keys;
        try {
            JsonElement el = PARSER.parse(json);
            collect(el, keys);
        } catch (JsonSyntaxException ignored) {
        }
        return keys;
    }

    private static void collect(JsonElement el, Set<String> out) {
        if (el == null || el.isJsonNull()) return;
        if (el.isJsonObject()) {
            for (Map.Entry<String, JsonElement> e : el.getAsJsonObject().entrySet()) {
                out.add(e.getKey());
                collect(e.getValue(), out);
            }
        } else if (el.isJsonArray()) {
            for (JsonElement child : el.getAsJsonArray()) collect(child, out);
        } // primitives: nothing to add
    }
}

