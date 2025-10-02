package burp.paramamador.datastore;

import java.time.Instant;
import java.util.*;

/**
 * Parameter occurrence summary.
 */
public class ParameterRecord {
    public final String name;
    public final Set<String> sources = Collections.synchronizedSet(new LinkedHashSet<>());
    public final Set<String> types = Collections.synchronizedSet(new LinkedHashSet<>()); // query/body/json/cookie
    public final List<String> exampleValues = Collections.synchronizedList(new ArrayList<>());
    public long count;
    public long firstSeen;
    public long lastSeen;
    public boolean onlyInCode = false;

    public ParameterRecord(String name) {
        this.name = name;
        long now = Instant.now().toEpochMilli();
        this.firstSeen = now;
        this.lastSeen = now;
    }

    public synchronized void touch() {
        lastSeen = Instant.now().toEpochMilli();
        count++;
    }

    public synchronized void addExample(String v) {
        if (v == null) return;
        if (exampleValues.size() < 3 && exampleValues.stream().noneMatch(v::equals)) exampleValues.add(v);
    }
}

