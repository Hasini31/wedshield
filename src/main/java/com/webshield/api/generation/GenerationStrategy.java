package com.webshield.api.generation;

/**
 * Strategy applied to synthesize an API test input or variation.
 */
public enum GenerationStrategy {
    // Valid strategies
    SCHEMA_VALID_MINIMAL("Minimal valid payload with required fields only"),
    SCHEMA_VALID_FULL("Full valid payload with all optional and required fields"),
    SCHEMA_VALID_RANDOM("Schema-compliant valid payload with randomized attributes"),

    // Invalid strategies (Negative testing)
    MISSING_REQUIRED_FIELD("Omits a required parameter or schema property"),
    TYPE_MISMATCH("Substitutes an incompatible data type for a parameter or property"),
    INVALID_FORMAT("Supplies an invalid format (e.g. malformed email, date, or UUID)"),
    INVALID_ENUM("Supplies an unlisted value for an enumerated field"),
    NULL_INJECTION("Injects null into a required or non-nullable field"),
    STRING_LENGTH_EXCEEDED("String length exceeds the declared maxLength constraint"),
    STRING_LENGTH_BELOW_MIN("String length is below the declared minLength constraint"),
    STRING_EMPTY("Empty string supplied where constraints or non-empty input required"),
    NUMERIC_BELOW_MIN("Numeric value is strictly below the minimum allowed bound"),
    NUMERIC_ABOVE_MAX("Numeric value strictly exceeds the maximum allowed bound"),
    NUMERIC_EXCLUSIVE_VIOLATION("Violates exclusive minimum or exclusive maximum constraint"),
    ARRAY_MAX_OVERFLOW("Array item count exceeds maxItems constraint"),
    ARRAY_MIN_UNDERFLOW("Array item count is strictly below minItems constraint"),
    UNEXPECTED_PROPERTY("Injects undeclared properties into an object with closed schema"),

    // Boundary value strategies
    NUMERIC_MIN_BOUNDARY("Tests exact minimum numeric bound"),
    NUMERIC_MAX_BOUNDARY("Tests exact maximum numeric bound"),
    STRING_MIN_LENGTH_BOUNDARY("Tests string with exact minimum length"),
    STRING_MAX_LENGTH_BOUNDARY("Tests string with exact maximum length"),
    ARRAY_EMPTY_BOUNDARY("Tests empty array representation"),
    ARRAY_MIN_ITEMS_BOUNDARY("Tests array with exact minItems count"),
    ARRAY_MAX_ITEMS_BOUNDARY("Tests array with exact maxItems count"),

    // Mutation strategies
    MUTATION_INPUT("Fuzzed or mutated input via schema-aware mutation operator");

    private final String description;

    GenerationStrategy(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}

