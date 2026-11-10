package com.webshield.api.generation;

import com.webshield.api.models.HttpMethod;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Immutable representation of a generated API test case ready for execution or analysis.
 */
public record ApiTestCase(
        String id,
        String endpointIdentifier,
        HttpMethod method,
        String path,
        TestCategory category,
        Map<String, Object> pathParameters,
        Map<String, Object> queryParameters,
        Map<String, String> headers,
        Map<String, String> cookies,
        Object requestBody,
        String contentType,
        GenerationStrategy strategy,
        Long randomSeed,
        String description,
        String targetedProperty,
        String targetedConstraint,
        String parentTestCaseId
) {
    public ApiTestCase {
        pathParameters = pathParameters != null ? Collections.unmodifiableMap(new LinkedHashMap<>(pathParameters)) : Collections.emptyMap();
        queryParameters = queryParameters != null ? Collections.unmodifiableMap(new LinkedHashMap<>(queryParameters)) : Collections.emptyMap();
        headers = headers != null ? Collections.unmodifiableMap(new LinkedHashMap<>(headers)) : Collections.emptyMap();
        cookies = cookies != null ? Collections.unmodifiableMap(new LinkedHashMap<>(cookies)) : Collections.emptyMap();
    }

    public boolean hasRequestBody() {
        return requestBody != null;
    }

    public boolean isExpectedValid() {
        return category == TestCategory.VALID;
    }

    public boolean isNegativeTest() {
        return category == TestCategory.INVALID;
    }

    public boolean isBoundaryTest() {
        return category == TestCategory.BOUNDARY;
    }

    public boolean isMutationTest() {
        return category == TestCategory.MUTATION;
    }
}

