package com.webshield.api.execution;

import com.webshield.api.generation.ApiTestCase;
import com.webshield.api.search.CandidateEvaluator;
import com.webshield.api.search.EvaluationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Adapter integrating ApiExecutionEngine with the evolutionary search engine (Module E).
 * Implements CandidateEvaluator by translating ApiTestCase to ApiExecutionRequest,
 * dispatching the request, and mapping ApiExecutionResponse to EvaluationResult.
 */
public class ApiCandidateEvaluator implements CandidateEvaluator {

    private static final Logger log = LoggerFactory.getLogger(ApiCandidateEvaluator.class);

    private final ApiExecutionEngine executionEngine;
    private final ApiRequestBuilder requestBuilder;
    private final String targetBaseUrl;
    private final Long apiProjectId;

    public ApiCandidateEvaluator(ApiExecutionEngine executionEngine, String targetBaseUrl) {
        this(executionEngine, targetBaseUrl, null);
    }

    public ApiCandidateEvaluator(ApiExecutionEngine executionEngine, String targetBaseUrl, Long apiProjectId) {
        this.executionEngine = Objects.requireNonNull(executionEngine, "executionEngine must not be null");
        this.targetBaseUrl = Objects.requireNonNull(targetBaseUrl, "targetBaseUrl must not be null");
        this.apiProjectId = apiProjectId;
        this.requestBuilder = new ApiRequestBuilder();
    }

    @Override
    public EvaluationResult evaluate(ApiTestCase testCase) {
        if (testCase == null) {
            return EvaluationResult.failure("UNKNOWN", "ApiTestCase is null");
        }

        String endpoint = testCase.endpointIdentifier() != null
                ? testCase.endpointIdentifier()
                : (testCase.method() != null ? testCase.method().name() : "GET") + " " + testCase.path();

        try {
            ApiExecutionRequest request = requestBuilder.buildRequest(targetBaseUrl, testCase, apiProjectId);
            ApiExecutionResponse response = executionEngine.execute(request);

            Map<String, String> flatHeaders = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> entry : response.responseHeaders().entrySet()) {
                if (!entry.getValue().isEmpty()) {
                    flatHeaders.put(entry.getKey(), entry.getValue().get(0));
                }
            }

            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("executionId", response.executionId());
            metadata.put("outcome", response.outcome().name());
            metadata.put("redirectCount", response.redirectCount());
            metadata.put("responseSize", response.responseSizeBytes());

            return new EvaluationResult(
                    response.statusCode(),
                    endpoint,
                    response.responseTimeMs(),
                    flatHeaders,
                    response.responseBody(),
                    response.connectionSuccessful(),
                    response.errorMessage(),
                    metadata
            );

        } catch (Exception e) {
            log.warn("Evaluation dispatch failure for {}: {}", endpoint, e.getMessage());
            return EvaluationResult.failure(endpoint, "Evaluation error: " + e.getMessage());
        }
    }

    public String getTargetBaseUrl() {
        return targetBaseUrl;
    }

    public Long getApiProjectId() {
        return apiProjectId;
    }
}

