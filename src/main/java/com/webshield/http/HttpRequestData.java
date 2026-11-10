package com.webshield.http;

import java.util.*;

/**
 * Encapsulates an outbound HTTP request.
 */
public class HttpRequestData {

    private final String url;
    private final String method; // GET, POST
    private final Map<String, List<String>> headers;
    private final String body;
    private final int timeoutSeconds;

    public HttpRequestData(String url, String method, Map<String, List<String>> headers,
                           String body, int timeoutSeconds) {
        this.url = Objects.requireNonNull(url, "Request URL must not be null");
        this.method = method != null ? method.toUpperCase(Locale.ROOT) : "GET";
        this.headers = headers != null ? new HashMap<>(headers) : new HashMap<>();
        this.body = body;
        this.timeoutSeconds = timeoutSeconds > 0 ? timeoutSeconds : 15;
    }

    public String getUrl() { return url; }
    public String getMethod() { return method; }
    public Map<String, List<String>> getHeaders() { return Collections.unmodifiableMap(headers); }
    public String getBody() { return body; }
    public int getTimeoutSeconds() { return timeoutSeconds; }

    public Optional<String> getFirstHeader(String name) {
        if (name == null) return Optional.empty();
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name) && !e.getValue().isEmpty()) {
                return Optional.of(e.getValue().getFirst());
            }
        }
        return Optional.empty();
    }
}

