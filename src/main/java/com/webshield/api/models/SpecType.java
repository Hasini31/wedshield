package com.webshield.api.models;

/**
 * Supported API specification standards.
 */
public enum SpecType {
    OPENAPI_3("OpenAPI 3.x"),
    SWAGGER_2("Swagger 2.0"),
    UNKNOWN("Unknown / Unsupported");

    private final String displayName;

    SpecType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}

