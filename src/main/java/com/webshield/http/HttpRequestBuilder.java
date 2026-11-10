package com.webshield.http;

import java.util.*;

/**
 * Fluent builder for {@link HttpRequestData}.
 */
public class HttpRequestBuilder {

    private String url;
    private String method = "GET";
    private final Map<String, List<String>> headers = new HashMap<>();
    private String body;
    private int timeoutSeconds = 15;

    public HttpRequestBuilder() {
        // Standard defensive headers
        header("User-Agent", "WebShield-Security-Assessment/1.0 (Defensive Educational Scanner)");
        header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        header("Accept-Language", "en-US,en;q=0.5");
    }

    public static HttpRequestBuilder create() {
        return new HttpRequestBuilder();
    }

    public static HttpRequestBuilder get(String url) {
        return new HttpRequestBuilder().url(url).method("GET");
    }

    public static HttpRequestBuilder post(String url, String body, String contentType) {
        HttpRequestBuilder b = new HttpRequestBuilder().url(url).method("POST").body(body);
        if (contentType != null) {
            b.header("Content-Type", contentType);
        } else {
            b.header("Content-Type", "application/x-www-form-urlencoded");
        }
        return b;
    }

    public HttpRequestBuilder url(String url) {
        this.url = url;
        return this;
    }

    public HttpRequestBuilder method(String method) {
        this.method = method;
        return this;
    }

    public HttpRequestBuilder header(String name, String value) {
        if (name != null && value != null) {
            headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
        }
        return this;
    }

    public HttpRequestBuilder headers(Map<String, String> map) {
        if (map != null) {
            map.forEach(this::header);
        }
        return this;
    }

    public HttpRequestBuilder body(String body) {
        this.body = body;
        return this;
    }

    public HttpRequestBuilder timeout(int seconds) {
        this.timeoutSeconds = seconds;
        return this;
    }

    public HttpRequestData build() {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalStateException("Request URL must be specified.");
        }
        return new HttpRequestData(url, method, headers, body, timeoutSeconds);
    }
}

