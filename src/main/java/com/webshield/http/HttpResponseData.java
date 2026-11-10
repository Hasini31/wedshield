package com.webshield.http;

import java.util.*;

/**
 * Encapsulates an HTTP response received from a target server.
 */
public class HttpResponseData {

    private final String url;
    private final int statusCode;
    private final Map<String, List<String>> headers;
    private final String body;
    private final long responseTimeMs;
    private final List<HttpCookieData> cookies;
    private final String redirectedTo;

    public HttpResponseData(String url, int statusCode, Map<String, List<String>> headers,
                            String body, long responseTimeMs, List<HttpCookieData> cookies,
                            String redirectedTo) {
        this.url = url;
        this.statusCode = statusCode;
        this.headers = headers != null ? new HashMap<>(headers) : new HashMap<>();
        this.body = body != null ? body : "";
        this.responseTimeMs = responseTimeMs;
        this.cookies = cookies != null ? new ArrayList<>(cookies) : new ArrayList<>();
        this.redirectedTo = redirectedTo;
    }

    public String getUrl() { return url; }
    public int getStatusCode() { return statusCode; }
    public Map<String, List<String>> getHeaders() { return Collections.unmodifiableMap(headers); }
    public String getBody() { return body; }
    public long getResponseTimeMs() { return responseTimeMs; }
    public List<HttpCookieData> getCookies() { return Collections.unmodifiableList(cookies); }
    public String getRedirectedTo() { return redirectedTo; }

    public boolean isSuccess() {
        return statusCode >= 200 && statusCode < 300;
    }

    public boolean isRedirect() {
        return statusCode >= 300 && statusCode < 400;
    }

    public boolean isClientError() {
        return statusCode >= 400 && statusCode < 500;
    }

    public boolean isServerError() {
        return statusCode >= 500 && statusCode < 600;
    }

    public Optional<String> getFirstHeader(String name) {
        if (name == null) return Optional.empty();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) {
                List<String> values = entry.getValue();
                if (values != null && !values.isEmpty()) {
                    return Optional.of(values.getFirst());
                }
            }
        }
        return Optional.empty();
    }

    public List<String> getHeaderValues(String name) {
        if (name == null) return Collections.emptyList();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue() != null ? Collections.unmodifiableList(entry.getValue()) : Collections.emptyList();
            }
        }
        return Collections.emptyList();
    }

    public String getContentType() {
        return getFirstHeader("Content-Type").orElse("");
    }
}

