package com.webshield.api.search;

import com.webshield.api.generation.ApiTestCase;

/**
 * Execution abstraction decoupling test generation and evolutionary search from real HTTP transmission.
 * Module F will supply the concrete production implementation.
 */
@FunctionalInterface
public interface CandidateEvaluator {

    /**
     * Evaluates an API test case and produces observable execution feedback.
     */
    EvaluationResult evaluate(ApiTestCase testCase);
}

