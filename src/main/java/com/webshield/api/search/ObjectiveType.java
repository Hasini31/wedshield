package com.webshield.api.search;

/**
 * Categories of independent testing objectives pursued during evolutionary search.
 */
public enum ObjectiveType {
    ENDPOINT_REACHED("Reach a declared API endpoint with an active request"),
    STATUS_CODE("Discover a distinct HTTP response status code for an endpoint"),
    BOUNDARY_EXERCISED("Exercise an input constraint boundary (numeric, string length, or array count)"),
    VALIDATION_TRIGGERED("Trigger an input validation error response (400 / 422)"),
    SERVER_ERROR("Discover an unhandled server error response (500-599)"),
    RESPONSE_BEHAVIOR("Observe a distinct response content type, structure, or header behavior");

    private final String description;

    ObjectiveType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}

