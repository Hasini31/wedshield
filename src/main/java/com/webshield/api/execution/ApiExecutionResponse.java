package com.webshield.api.execution;

import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Immutable representation of the execution observation resulting from an API HTTP dispatch.
 */
public record ApiExecutionResponse(
        String executionId,
        String testCaseId,
        int statusCode,
        Map<String, List<String>> responseHeaders,
        String responseBody,
        String contentType,
        long responseSizeBytes,
        long responseTimeMs,
        int redirectCount,
        List<String> redirectUrls,
        boolean connectionSuccessful,
        ExecutionOutcome outcome,
        String errorMessage,
        Instant executionTimestamp
) implements Serializable {

    public ApiExecutionResponse {
        responseHeaders = responseHeaders != null ? Collections.unmodifiableMap(new LinkedHashMap<>(responseHeaders)) : Collections.emptyMap();
        redirectUrls = redirectUrls != null ? List.copyOf(redirectUrls) : List.of();
        responseBody = responseBody != null ? responseBody : "";
        executionTimestamp = executionTimestamp != null ? executionTimestamp : Instant.now();
    }

    public static ApiExecutionResponse failure(String executionId, String testCaseId, ExecutionOutcome outcome, String errorMessage) {
        return new ApiExecutionResponse(
                executionId,
                testCaseId,
                0,
                Map.of(),
                "",
                "unknown",
                0L,
                0L,
                0,
                List.of(),
                false,
                outcome,
                errorMessage,
                Instant.now()
        );
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

