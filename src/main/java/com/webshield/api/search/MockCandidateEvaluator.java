package com.webshield.api.search;

import com.webshield.api.generation.ApiTestCase;
import com.webshield.api.generation.GenerationStrategy;
import com.webshield.api.generation.TestCategory;

import java.util.*;
import java.util.function.Predicate;

/**
 * Deterministic local mock evaluator simulating API response behaviors for evolutionary testing.
 * Enables fast, isolated, reproducible unit and integration tests without network I/O.
 */
public class MockCandidateEvaluator implements CandidateEvaluator {

    private final Map<String, Integer> explicitStatusMappings = new LinkedHashMap<>();
    private final List<Predicate<ApiTestCase>> failureRules = new ArrayList<>();
    private boolean simulateFailures = false;

    public MockCandidateEvaluator() {
    }

    public void mapStatus(String endpointIdentifier, int statusCode) {
        explicitStatusMappings.put(endpointIdentifier, statusCode);
    }

    public void addFailureRule(Predicate<ApiTestCase> rule) {
        failureRules.add(rule);
    }

    public void setSimulateFailures(boolean simulate) {
        this.simulateFailures = simulate;
    }

    @Override
    public EvaluationResult evaluate(ApiTestCase testCase) {
        if (testCase == null) {
            return EvaluationResult.failure("UNKNOWN", "Test case is null");
        }

        String endpoint = testCase.endpointIdentifier() != null
                ? testCase.endpointIdentifier()
                : testCase.method() + " " + testCase.path();

        // Check simulated connection failures
        if (simulateFailures || failureRules.stream().anyMatch(rule -> rule.test(testCase))) {
            return EvaluationResult.failure(endpoint, "Connection refused / simulated network exception");
        }

        // Check explicit endpoint status mappings
        if (explicitStatusMappings.containsKey(endpoint)) {
            int code = explicitStatusMappings.get(endpoint);
            return EvaluationResult.successful(code, endpoint, 15L, Map.of("status", code));
        }

        // Deterministic status code derivation based on test category & strategy
        int statusCode = deriveStatusCode(testCase);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("endpoint", endpoint);
        body.put("statusCode", statusCode);
        body.put("strategy", testCase.strategy() != null ? testCase.strategy().name() : "NONE");
        body.put("category", testCase.category() != null ? testCase.category().name() : "NONE");

        return EvaluationResult.successful(statusCode, endpoint, 12L, body);
    }

    private int deriveStatusCode(ApiTestCase testCase) {
        if (testCase.category() == TestCategory.VALID) {
            return testCase.method() == com.webshield.api.models.HttpMethod.POST ? 201 : 200;
        }

        if (testCase.category() == TestCategory.BOUNDARY) {
            GenerationStrategy s = testCase.strategy();
            if (s == GenerationStrategy.ARRAY_EMPTY_BOUNDARY || s == GenerationStrategy.STRING_MIN_LENGTH_BOUNDARY) {
                return 200;
            }
            return 422; // Unprocessable Entity
        }

        if (testCase.category() == TestCategory.MUTATION) {
            String constraint = testCase.targetedConstraint();
            if (constraint != null) {
                if (constraint.contains("OVERFLOW") || constraint.contains("CONTROL_CHARS")) {
                    return 500; // Simulated server error
                }
                if (constraint.contains("SPECIAL_CHARS") || constraint.contains("QUOTES")
                        || constraint.contains("TYPE_MISMATCH") || constraint.contains("INVALID")) {
                    return 400; // Bad request
                }
                if (constraint.contains("OUTSIDE_BOUNDS")) {
                    return 422;
                }
            }
            return 400;
        }

        // TestCategory.INVALID
        GenerationStrategy strategy = testCase.strategy();
        if (strategy == GenerationStrategy.INVALID_FORMAT || strategy == GenerationStrategy.NUMERIC_BELOW_MIN
                || strategy == GenerationStrategy.NUMERIC_ABOVE_MAX) {
            return 422;
        }
        return 400;
    }
}

