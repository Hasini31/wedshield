package com.webshield.api.search;

import com.webshield.api.generation.ApiTestCase;

import java.util.List;
import java.util.Map;

/**
 * Evaluates candidate API test cases against independent search objectives.
 * Implements transparent, observable fitness metrics with clear rationales.
 */
public class FitnessEvaluator {

    public FitnessScore evaluate(SearchObjective objective, ApiTestCase candidate, EvaluationResult execution) {
        if (objective == null || candidate == null) {
            return FitnessScore.unusable("Objective or candidate is null");
        }
        if (execution == null) {
            return FitnessScore.executionFailure("No execution observation provided");
        }
        if (!execution.connectionSuccessful()) {
            return FitnessScore.executionFailure("Connection failure: " + execution.errorMessage());
        }

        int complexity = computeComplexity(candidate);
        String targetEndpoint = objective.getEndpointIdentifier();
        String actualEndpoint = execution.endpointIdentifier();

        // 1. Endpoint Check: Does the test target the intended endpoint?
        if (!endpointMatches(targetEndpoint, actualEndpoint)) {
            return FitnessScore.progressing(1.0, 0.0, complexity,
                    "Target endpoint mismatch: expected " + targetEndpoint + " but was " + actualEndpoint);
        }

        // 2. Objective-specific fitness evaluation
        return switch (objective.getType()) {
            case ENDPOINT_REACHED -> FitnessScore.achieved(complexity,
                    "Successfully reached target endpoint: " + targetEndpoint);

            case STATUS_CODE -> evaluateStatusCodeObjective(objective, execution, complexity);

            case BOUNDARY_EXERCISED -> evaluateBoundaryObjective(objective, candidate, execution, complexity);

            case VALIDATION_TRIGGERED -> evaluateValidationObjective(objective, candidate, execution, complexity);

            case SERVER_ERROR -> evaluateServerErrorObjective(objective, execution, complexity);

            case RESPONSE_BEHAVIOR -> evaluateResponseBehaviorObjective(objective, execution, complexity);
        };
    }

    private FitnessScore evaluateStatusCodeObjective(SearchObjective objective, EvaluationResult execution, int complexity) {
        int targetStatus;
        try {
            targetStatus = Integer.parseInt(objective.getTargetValue());
        } catch (NumberFormatException e) {
            return FitnessScore.unusable("Malformed target status code in objective: " + objective.getTargetValue());
        }

        int actualStatus = execution.statusCode();
        if (actualStatus == targetStatus) {
            return FitnessScore.achieved(complexity,
                    "Exact target HTTP status " + targetStatus + " achieved.");
        }

        // Proximity heuristic based on status code class
        int targetClass = targetStatus / 100;
        int actualClass = actualStatus / 100;
        int diff = Math.abs(actualStatus - targetStatus);

        double distance;
        if (targetClass == actualClass) {
            // Same class (e.g. 400 vs 422, or 200 vs 201)
            distance = 0.1 + (Math.min(diff, 99) / 1000.0);
        } else {
            // Different class (e.g. 200 vs 400)
            distance = 0.5 + (Math.min(diff, 500) / 1000.0);
        }
        double fitness = Math.max(0.0, 1.0 - distance);

        return FitnessScore.progressing(distance, fitness, complexity,
                "Observed status " + actualStatus + ", target was " + targetStatus + " (distance=" + String.format("%.3f", distance) + ")");
    }

    private FitnessScore evaluateBoundaryObjective(SearchObjective objective, ApiTestCase candidate, EvaluationResult execution, int complexity) {
        String targetVal = objective.getTargetValue(); // e.g. "count=min" or "name=maxLength"
        String targetedProperty = candidate.targetedProperty();

        boolean propertyMatched = targetedProperty != null && targetVal.contains(targetedProperty);
        boolean isBoundaryType = candidate.isBoundaryTest() || (candidate.strategy() != null && candidate.strategy().name().contains("BOUNDARY"));

        if (propertyMatched && isBoundaryType) {
            return FitnessScore.achieved(complexity,
                    "Target boundary condition successfully exercised on property '" + targetedProperty + "'");
        } else if (propertyMatched) {
            return FitnessScore.progressing(0.3, 0.7, complexity,
                    "Targeted property matched but strategy was not boundary");
        } else if (isBoundaryType) {
            return FitnessScore.progressing(0.5, 0.5, complexity,
                    "Boundary strategy exercised but on different property: " + targetedProperty);
        } else {
            return FitnessScore.progressing(0.8, 0.2, complexity,
                    "Candidate did not exercise target boundary condition");
        }
    }

    private FitnessScore evaluateValidationObjective(SearchObjective objective, ApiTestCase candidate, EvaluationResult execution, int complexity) {
        int status = execution.statusCode();
        boolean isClientError = status == 400 || status == 422;

        if (isClientError) {
            return FitnessScore.achieved(complexity,
                    "Input validation error successfully triggered (HTTP " + status + ")");
        } else if (status >= 500) {
            return FitnessScore.progressing(0.3, 0.7, complexity,
                    "Server-side failure triggered rather than clean validation error");
        } else {
            return FitnessScore.progressing(0.8, 0.2, complexity,
                    "Expected validation error, received success HTTP " + status);
        }
    }

    private FitnessScore evaluateServerErrorObjective(SearchObjective objective, EvaluationResult execution, int complexity) {
        int status = execution.statusCode();
        if (status >= 500 && status < 600) {
            return FitnessScore.achieved(complexity,
                    "Unhandled 5xx server error detected (HTTP " + status + ")");
        } else if (status >= 400) {
            return FitnessScore.progressing(0.4, 0.6, complexity,
                    "Client error triggered (HTTP " + status + "), progressing toward unhandled failure");
        } else {
            return FitnessScore.progressing(0.9, 0.1, complexity,
                    "Request succeeded (HTTP " + status + ")");
        }
    }

    private FitnessScore evaluateResponseBehaviorObjective(SearchObjective objective, EvaluationResult execution, int complexity) {
        String targetBehavior = objective.getTargetValue();
        Map<String, String> headers = execution.responseHeaders();

        boolean matched = headers.entrySet().stream()
                .anyMatch(e -> e.getKey().equalsIgnoreCase(targetBehavior) || e.getValue().toLowerCase().contains(targetBehavior.toLowerCase()));

        if (matched) {
            return FitnessScore.achieved(complexity,
                    "Observed target response behavior: " + targetBehavior);
        }
        return FitnessScore.progressing(0.5, 0.5, complexity,
                "Behavior '" + targetBehavior + "' not observed in response");
    }

    private boolean endpointMatches(String target, String actual) {
        if (target == null || actual == null) return false;
        return target.trim().equalsIgnoreCase(actual.trim());
    }

    public static int computeComplexity(ApiTestCase tc) {
        int count = 0;
        count += tc.pathParameters().size();
        count += tc.queryParameters().size();
        count += tc.headers().size();
        if (tc.hasRequestBody()) {
            if (tc.requestBody() instanceof Map<?, ?> map) {
                count += map.size() * 2;
            } else if (tc.requestBody() instanceof List<?> list) {
                count += list.size() * 2;
            } else {
                count += 2;
            }
        }
        return count;
    }
}

