package com.webshield.api.execution;

import com.webshield.api.models.HttpMethod;

import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Immutable representation of a fully resolved API execution request ready for dispatch.
 */
public record ApiExecutionRequest(
        String testCaseId,
        Long apiProjectId,
        String targetBaseUrl,
        HttpMethod method,
        String resolvedPath,
        String fullUrl,
        Map<String, Object> queryParameters,
        Map<String, String> headers,
        Map<String, String> cookies,
        String requestBody,
        String contentType,
        Instant executionTimestamp,
        Map<String, Object> metadata
) implements Serializable {

    public ApiExecutionRequest {
        queryParameters = queryParameters != null ? Collections.unmodifiableMap(new LinkedHashMap<>(queryParameters)) : Collections.emptyMap();
        headers = headers != null ? Collections.unmodifiableMap(new LinkedHashMap<>(headers)) : Collections.emptyMap();
        cookies = cookies != null ? Collections.unmodifiableMap(new LinkedHashMap<>(cookies)) : Collections.emptyMap();
        metadata = metadata != null ? Collections.unmodifiableMap(new LinkedHashMap<>(metadata)) : Collections.emptyMap();
        executionTimestamp = executionTimestamp != null ? executionTimestamp : Instant.now();
    }

    public boolean hasBody() {
        return requestBody != null && !requestBody.isBlank();
    }

    public boolean isSafeMethod() {
        return method == HttpMethod.GET || method == HttpMethod.HEAD || method == HttpMethod.OPTIONS;
    }
}

