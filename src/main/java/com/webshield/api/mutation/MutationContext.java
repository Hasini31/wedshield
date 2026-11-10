package com.webshield.api.mutation;

import java.io.Serializable;

/**
 * Immutable metadata tracking the lineage, operator, target, and value transformations of a mutation.
 */
public record MutationContext(
        String parentTestCaseId,
        MutationOperatorType operatorType,
        String targetedField,
        Object originalValue,
        Object mutatedValue,
        int generation,
        long randomSeed,
        String description
) implements Serializable {

    public MutationCategory getCategory() {
        return operatorType != null ? operatorType.getCategory() : null;
    }

    public boolean hasParent() {
        return parentTestCaseId != null && !parentTestCaseId.isBlank();
    }
}

