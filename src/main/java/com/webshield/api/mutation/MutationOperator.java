package com.webshield.api.mutation;

import com.webshield.api.models.ApiSchema;

import java.util.Random;

/**
 * Strategy interface representing an individual schema-aware mutation operator.
 */
public interface MutationOperator {

    /**
     * Identifies the operator type and its category.
     */
    MutationOperatorType getType();

    /**
     * Convenience method returning the high-level category of this operator.
     */
    default MutationCategory getCategory() {
        return getType().getCategory();
    }

    /**
     * Determines whether this operator is applicable to the given target value and schema.
     */
    boolean canApply(Object target, ApiSchema schema);

    /**
     * Applies the mutation logic and returns the mutated value or structure.
     */
    Object apply(Object target, ApiSchema schema, Random random);
}

