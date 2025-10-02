package burp.paramamador.datastore;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public class EndpointRecord {
    public enum Type { ABSOLUTE, RELATIVE, TEMPLATE }

    public final String endpointString;
    public final Set<String> sources = Collections.synchronizedSet(new LinkedHashSet<>()); // file URLs
    public final Type type;
    public boolean inScope;
    public String contextSnippet;
    public long firstSeen;

    public EndpointRecord(String endpointString, Type type, boolean inScope, String contextSnippet) {
        this.endpointString = endpointString;
        this.type = type;
        this.inScope = inScope;
        this.contextSnippet = contextSnippet;
        this.firstSeen = Instant.now().toEpochMilli();
    }
}

