package com.webshield.api.llm;

import java.time.Duration;

/**
 * Immutable configuration settings for LLM provider integration.
 */
public record LlmConfiguration(
        boolean enabled,
        String providerName,
        String endpointUrl,
        String apiKey,
        String modelName,
        double temperature,
        int maxTokens,
        Duration timeout,
        boolean externalSharingAllowed
) {
    public static final String DEFAULT_PROVIDER = "mock";
    public static final String DEFAULT_ENDPOINT = "https://api.openai.com/v1/chat/completions";
    public static final String DEFAULT_MODEL = "gpt-4o-mini";
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(20);

    public LlmConfiguration {
        providerName = (providerName != null && !providerName.isBlank()) ? providerName : DEFAULT_PROVIDER;
        endpointUrl = (endpointUrl != null && !endpointUrl.isBlank()) ? endpointUrl : DEFAULT_ENDPOINT;
        modelName = (modelName != null && !modelName.isBlank()) ? modelName : DEFAULT_MODEL;
        timeout = timeout != null ? timeout : DEFAULT_TIMEOUT;
        temperature = Math.max(0.0, Math.min(1.0, temperature));
        maxTokens = maxTokens > 0 ? maxTokens : 1000;
    }

    /**
     * Creates a secure default configuration attempting resolution from environment variables.
     */
    public static LlmConfiguration fromEnvironment() {
        String key = System.getenv("WEBSHIELD_LLM_API_KEY");
        if (key == null || key.isBlank()) {
            key = System.getenv("OPENAI_API_KEY");
        }
        String endpoint = System.getenv("WEBSHIELD_LLM_ENDPOINT");
        String model = System.getenv("WEBSHIELD_LLM_MODEL");
        String provider = System.getenv("WEBSHIELD_LLM_PROVIDER");

        boolean isKeyPresent = key != null && !key.isBlank();
        return new LlmConfiguration(
                isKeyPresent,
                (provider != null && !provider.isBlank()) ? provider : (isKeyPresent ? "openai" : "mock"),
                (endpoint != null && !endpoint.isBlank()) ? endpoint : DEFAULT_ENDPOINT,
                isKeyPresent ? key : "",
                (model != null && !model.isBlank()) ? model : DEFAULT_MODEL,
                0.2,
                1024,
                DEFAULT_TIMEOUT,
                false
        );
    }

    /**
     * Returns a copy with external sharing permission updated.
     */
    public LlmConfiguration withConsent(boolean consent) {
        return new LlmConfiguration(
                this.enabled,
                this.providerName,
                this.endpointUrl,
                this.apiKey,
                this.modelName,
                this.temperature,
                this.maxTokens,
                this.timeout,
                consent
        );
    }
}

