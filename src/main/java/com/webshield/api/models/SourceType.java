package com.webshield.api.models;

/**
 * Origin of an imported API specification.
 */
public enum SourceType {
    FILE_UPLOAD("File Upload"),
    URL("URL");

    private final String displayName;

    SourceType(String displayName) {
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

