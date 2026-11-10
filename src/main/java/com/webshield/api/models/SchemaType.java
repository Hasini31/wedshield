package com.webshield.api.models;

import java.util.Locale;

/**
 * Data types supported by OpenAPI and JSON Schema.
 */
public enum SchemaType {
    STRING("string"),
    INTEGER("integer"),
    NUMBER("number"),
    BOOLEAN("boolean"),
    OBJECT("object"),
    ARRAY("array"),
    ANY("any");

    private final String value;

    SchemaType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static SchemaType fromString(String type) {
        if (type == null || type.isBlank()) {
            return ANY;
        }
        String normalized = type.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "string" -> STRING;
            case "integer" -> INTEGER;
            case "number" -> NUMBER;
            case "boolean" -> BOOLEAN;
            case "object" -> OBJECT;
            case "array" -> ARRAY;
            default -> ANY;
        };
    }
}

