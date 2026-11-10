package com.webshield.api.models;

/**
 * Serialization formats for API specifications.
 */
public enum SpecFormat {
    JSON("JSON"),
    YAML("YAML");

    private final String displayName;

    SpecFormat(String displayName) {
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

