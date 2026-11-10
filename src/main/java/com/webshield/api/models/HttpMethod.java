package com.webshield.api.models;

import java.util.Locale;

/**
 * Standard HTTP methods supported in OpenAPI operations.
 */
public enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    TRACE;

    public static HttpMethod fromString(String method) {
        if (method == null || method.isBlank()) {
            return null;
        }
        try {
            return HttpMethod.valueOf(method.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}

