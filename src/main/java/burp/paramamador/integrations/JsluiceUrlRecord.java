package burp.paramamador.integrations;

import java.util.List;
import java.util.Map;

public class JsluiceUrlRecord {
    public final String url;
    public final List<String> queryParams;
    public final List<String> bodyParams;
    public final String method;
    public final String type;
    public final String filename;
    public final String contentType;
    public final Map<String,String> headers;

    public JsluiceUrlRecord(String url, List<String> queryParams, List<String> bodyParams,
                            String method, String type, String filename, String contentType,
                            Map<String,String> headers) {
        this.url = url;
        this.queryParams = queryParams;
        this.bodyParams = bodyParams;
        this.method = method;
        this.type = type;
        this.filename = filename;
        this.contentType = contentType;
        this.headers = headers;
    }
}

