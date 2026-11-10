package com.webshield.api.generation;

/**
 * Classification of an automated API test case.
 */
public enum TestCategory {
    VALID("Valid / Positive Testing"),
    INVALID("Invalid / Negative Testing"),
    BOUNDARY("Boundary Value Testing"),
    MUTATION("Input Mutation / Fuzzing Testing");

    private final String description;

    TestCategory(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}

