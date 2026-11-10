package com.webshield.api.mutation;

import com.webshield.api.models.ApiSchema;

/**
 * Boolean mutation operators covering inversion, null injection, and optional removal.
 */
public class BooleanMutation {

    /**
     * Inverts a boolean value (true -> false, false -> true).
     */
    public static Boolean invert(Boolean input) {
        if (input == null) return Boolean.TRUE;
        return !input;
    }

    /**
     * Injects null into the field.
     */
    public static Boolean nullInjection() {
        return null;
    }

    /**
     * Applies a boolean mutation operator.
     */
    public static Boolean apply(MutationOperatorType type, Boolean input, ApiSchema schema) {
        return switch (type) {
            case BOOLEAN_INVERT -> invert(input);
            case BOOLEAN_NULL_INJECT -> nullInjection();
            case BOOLEAN_REMOVE_OPTIONAL -> null;
            default -> input != null ? input : Boolean.FALSE;
        };
    }
}

