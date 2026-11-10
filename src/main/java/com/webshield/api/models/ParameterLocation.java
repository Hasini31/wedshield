package com.webshield.api.models;

import java.util.Locale;

/**
 * Location of an API parameter in an HTTP request.
 */
public enum ParameterLocation {
    PATH("path"),
    QUERY("query"),
    HEADER("header"),
    COOKIE("cookie");

    private final String value;

    ParameterLocation(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static ParameterLocation fromString(String in) {
        if (in == null || in.isBlank()) {
            return QUERY;
        }
        String normalized = in.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "path" -> PATH;
            case "header" -> HEADER;
            case "cookie" -> COOKIE;
            default -> QUERY;
        };
    }
}

