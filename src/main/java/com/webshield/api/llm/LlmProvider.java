package com.webshield.api.llm;

/**
 * Provider-independent interface for LLM operations.
 */
public interface LlmProvider {

    /**
     * Executes an explanation generation request against the configured LLM endpoint.
     */
    LlmResponse generateExplanation(LlmRequest request, LlmConfiguration config) throws LlmException;

    /**
     * Returns true if the provider is currently available and configured.
     */
    boolean isAvailable(LlmConfiguration config);

    /**
     * Unique identifier for this provider (e.g. "openai", "ollama", "mock").
     */
    String getProviderName();
}

