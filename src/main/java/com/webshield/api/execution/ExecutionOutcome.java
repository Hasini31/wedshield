package com.webshield.api.execution;

/**
 * High-level categorization of the execution outcome of an API request.
 * Note: These classify operational transport and HTTP response outcomes, not security vulnerabilities.
 */
public enum ExecutionOutcome {
    SUCCESS("Request succeeded with a 2xx HTTP response"),
    CLIENT_ERROR("Request completed with a 4xx HTTP client error response"),
    SERVER_ERROR("Request completed with a 5xx HTTP server error response"),
    CONNECTION_ERROR("Transport-level connection failure (DNS resolution, reset, refused)"),
    TIMEOUT("Request timed out during connection establishment or response read"),
    REDIRECT_BLOCKED("Redirect destination was blocked by scope policy or exceeded redirect threshold"),
    POLICY_BLOCKED("Request was blocked by SSRF safeguards, forbidden method, or authorization scope"),
    INVALID_REQUEST("Request was malformed, invalid URI, or unsupported configuration"),
    EXECUTION_ERROR("Unexpected internal runtime failure during request dispatch");

    private final String description;

    ExecutionOutcome(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public boolean isSuccessful() {
        return this == SUCCESS;
    }

    public boolean isHttpError() {
        return this == CLIENT_ERROR || this == SERVER_ERROR;
    }

    public boolean isBlocked() {
        return this == POLICY_BLOCKED || this == REDIRECT_BLOCKED;
    }
}

