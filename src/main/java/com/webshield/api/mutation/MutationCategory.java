package com.webshield.api.mutation;

/**
 * High-level category of mutation applied to API inputs and structures.
 */
public enum MutationCategory {
    STRING("String value mutations and encoding edge cases"),
    NUMERIC("Numeric value modifications, boundaries, and overflow limits"),
    BOOLEAN("Boolean inversions and null injections"),
    ENUM("Enumeration substitutions and invalid value injections"),
    STRUCTURE("JSON structural transformations, removals, additions, and type shifts");

    private final String description;

    MutationCategory(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}

