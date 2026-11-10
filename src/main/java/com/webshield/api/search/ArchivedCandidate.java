package com.webshield.api.search;

import com.webshield.api.generation.ApiTestCase;

import java.io.Serializable;

/**
 * Encapsulates an archived candidate test case, its execution observation, fitness score, and generation.
 */
public record ArchivedCandidate(
        ApiTestCase testCase,
        EvaluationResult execution,
        FitnessScore fitness,
        int generationAchieved
) implements Serializable {

    public String getCandidateId() {
        return testCase != null ? testCase.id() : null;
    }

    public boolean isAchieved() {
        return fitness != null && fitness.isAchieved();
    }
}

