package com.webshield.api.llm;

import java.io.Serializable;
import java.util.Map;

/**
 * Immutable request payload dispatched to an LLM provider.
 */
public record LlmRequest(
        String prompt,
        String systemPrompt,
        Map<String, String> findingContext,
        int maxTokens,
        double temperature
) implements Serializable {

    public LlmRequest {
        prompt = prompt != null ? prompt : "";
        systemPrompt = systemPrompt != null ? systemPrompt : "";
        findingContext = findingContext != null ? Map.copyOf(findingContext) : Map.of();
        maxTokens = maxTokens > 0 ? maxTokens : 1000;
        temperature = Math.max(0.0, Math.min(1.0, temperature));
    }
}

