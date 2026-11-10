package com.webshield.api.mutation;

import com.webshield.api.generation.ApiTestCase;

import java.io.Serializable;

/**
 * Encapsulates a mutated API test case and its corresponding mutation context lineage.
 */
public record MutationResult(
        ApiTestCase testCase,
        MutationContext context
) implements Serializable {

    public String getId() {
        return testCase != null ? testCase.id() : null;
    }

    public String getParentTestCaseId() {
        return context != null ? context.parentTestCaseId() : null;
    }

    public MutationOperatorType getOperatorType() {
        return context != null ? context.operatorType() : null;
    }

    public int getGeneration() {
        return context != null ? context.generation() : 0;
    }

    public String getTargetedField() {
        return context != null ? context.targetedField() : null;
    }
}

