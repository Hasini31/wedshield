package com.webshield.config;

import com.webshield.auth.AuthException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Centralized exception handler for WebShield.
 * Standardizes exception formatting, logging, and user-facing error reporting.
 */
@Component
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * Formats an exception into a sanitized, user-friendly error string for UI alerts.
     */
    public static String handle(Throwable t, String contextMessage) {
        if (t == null) return "An unexpected error occurred.";

        log.error("Operation failed in context: {}", contextMessage, t);

        if (t instanceof AuthException) {
            return t.getMessage();
        }
        if (t instanceof IllegalArgumentException) {
            return "Invalid input: " + t.getMessage();
        }
        if (t instanceof IllegalStateException) {
            return "Application state error: " + t.getMessage();
        }
        if (t.getCause() != null && t.getCause() instanceof AuthException) {
            return t.getCause().getMessage();
        }

        return (contextMessage != null ? contextMessage + ": " : "") + t.getMessage();
    }
}

