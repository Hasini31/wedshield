package com.webshield.api.search;

import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Structured, immutable execution observation produced by evaluating an API test case.
 * Designed to cleanly decouple evolutionary search from the underlying HTTP client (Module F).
 */
public record EvaluationResult(
        int statusCode,
        String endpointIdentifier,
        long responseTimeMs,
        Map<String, String> responseHeaders,
        Object responseBody,
        boolean connectionSuccessful,
        String errorMessage,
        Map<String, Object> metadata
) implements Serializable {

    public EvaluationResult {
        responseHeaders = responseHeaders != null ? Collections.unmodifiableMap(new LinkedHashMap<>(responseHeaders)) : Collections.emptyMap();
        metadata = metadata != null ? Collections.unmodifiableMap(new LinkedHashMap<>(metadata)) : Collections.emptyMap();
    }

    public static EvaluationResult successful(int statusCode, String endpointIdentifier, long responseTimeMs, Object body) {
        return new EvaluationResult(statusCode, endpointIdentifier, responseTimeMs, Map.of("content-type", "application/json"), body, true, null, Map.of());
    }

    public static EvaluationResult failure(String endpointIdentifier, String error) {
        return new EvaluationResult(0, endpointIdentifier, 0L, Map.of(), null, false, error, Map.of());
    }

    public boolean is2xxSuccess() {
        return statusCode >= 200 && statusCode < 300;
    }

    public boolean is4xxClientError() {
        return statusCode >= 400 && statusCode < 500;
    }

    public boolean is5xxServerError() {
        return statusCode >= 500 && statusCode < 600;
    }
}

