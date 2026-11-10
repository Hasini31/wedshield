package com.webshield.api.llm;

/**
 * Runtime exception thrown for LLM integration, provider dispatch, or validation failures.
 */
public class LlmException extends RuntimeException {

    private final String providerName;
    private final boolean retryable;

    public LlmException(String message) {
        this(message, null, null, false);
    }

    public LlmException(String message, Throwable cause) {
        this(message, null, cause, false);
    }

    public LlmException(String message, String providerName, Throwable cause, boolean retryable) {
        super(message, cause);
        this.providerName = providerName;
        this.retryable = retryable;
    }

    public String getProviderName() {
        return providerName;
    }

    public boolean isRetryable() {
        return retryable;
    }
}

