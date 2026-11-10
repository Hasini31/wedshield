package com.webshield.api.generation;

import com.webshield.api.models.ApiEndpoint;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Factory responsible for assembling uniform {@link ApiTestCase} instances with metadata.
 */
public class TestCaseFactory {

    private final AtomicInteger sequence = new AtomicInteger(1);

    public ApiTestCase createTestCase(ApiEndpoint endpoint,
                                      TestCategory category,
                                      GenerationStrategy strategy,
                                      Map<String, Object> pathParams,
                                      Map<String, Object> queryParams,
                                      Map<String, String> headers,
                                      Map<String, String> cookies,
                                      Object requestBody,
                                      String contentType,
                                      Long randomSeed,
                                      String description,
                                      String targetedProperty,
                                      String targetedConstraint,
                                      String parentTestCaseId) {
        String testCaseId = generateId(endpoint, strategy);
        return new ApiTestCase(
                testCaseId,
                endpoint.getIdentifier(),
                endpoint.getMethod(),
                endpoint.getPath(),
                category,
                pathParams,
                queryParams,
                headers,
                cookies,
                requestBody,
                contentType != null ? contentType : "application/json",
                strategy,
                randomSeed,
                description,
                targetedProperty,
                targetedConstraint,
                parentTestCaseId
        );
    }

    private String generateId(ApiEndpoint endpoint, GenerationStrategy strategy) {
        String cleanPath = endpoint.getPath()
                .replaceAll("[^a-zA-Z0-9]", "-")
                .replaceAll("-+", "-")
                .replaceAll("^-|-$", "");
        if (cleanPath.isBlank()) {
            cleanPath = "root";
        }
        int num = sequence.getAndIncrement();
        return String.format("TC-%s-%s-%s-%03d",
                endpoint.getMethod().name(), cleanPath, strategy.name(), num);
    }

    public void reset() {
        sequence.set(1);
    }
}

