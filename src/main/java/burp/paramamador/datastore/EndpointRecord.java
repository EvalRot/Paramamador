package burp.paramamador.datastore;

import java.time.Instant;

public class EndpointRecord {
    public enum Type { ABSOLUTE, RELATIVE, TEMPLATE, CONCAT }

    public final String endpointString;
    public final String source; // JS file URL this endpoint was found in
    public final Type type;
    public boolean inScope;
    public String contextSnippet;
    public String pattern; // regex used to capture this endpoint
    public boolean notSure;
    public boolean falsePositive;
    public long firstSeen;

    public EndpointRecord(String endpointString, String source, Type type, boolean inScope, String contextSnippet, String pattern) {
        this.endpointString = endpointString;
        this.source = source;
        this.type = type;
        this.inScope = inScope;
        this.contextSnippet = contextSnippet;
        this.pattern = pattern;
        this.firstSeen = Instant.now().toEpochMilli();
    }
}
