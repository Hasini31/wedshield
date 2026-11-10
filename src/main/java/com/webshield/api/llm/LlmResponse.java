package com.webshield.api.llm;

import java.io.Serializable;

/**
 * Immutable response returned by an LLM provider.
 */
public record LlmResponse(
        boolean success,
        String rawContent,
        String model,
        int tokensUsed,
        long executionTimeMs,
        String errorMessage
) implements Serializable {

    public static LlmResponse successful(String content, String model, int tokensUsed, long elapsedMs) {
        return new LlmResponse(true, content, model, tokensUsed, elapsedMs, null);
    }

    public static LlmResponse failed(String errorMessage, String model, long elapsedMs) {
        return new LlmResponse(false, null, model, 0, elapsedMs, errorMessage);
    }
}

