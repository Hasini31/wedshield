package com.webshield.api.llm;

import java.time.Duration;

/**
 * Immutable configuration settings for LLM provider integration.
 * Prioritizes Google Gemini AI Studio integration.
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
    public static final String DEFAULT_PROVIDER = "gemini";
    public static final String DEFAULT_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent";
    public static final String DEFAULT_MODEL = "gemini-3.1-flash-lite";
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(60);

    // Configured via GEMINI_API_KEY environment variable
    public static final String CONFIGURED_FALLBACK_KEY = "";

    public LlmConfiguration {
        providerName = (providerName != null && !providerName.isBlank()) ? providerName : DEFAULT_PROVIDER;
        endpointUrl = (endpointUrl != null && !endpointUrl.isBlank()) ? endpointUrl : DEFAULT_ENDPOINT;
        modelName = (modelName != null && !modelName.isBlank()) ? modelName : DEFAULT_MODEL;
        timeout = timeout != null ? timeout : DEFAULT_TIMEOUT;
        temperature = Math.max(0.0, Math.min(1.0, temperature));
        maxTokens = maxTokens > 0 ? maxTokens : 8192;
    }

    /**
     * Creates configuration from GEMINI_API_KEY environment variable or configured secure key.
     */
    public static LlmConfiguration fromEnvironment() {
        String key = System.getenv("GEMINI_API_KEY");
        if (key == null || key.isBlank()) {
            key = System.getProperty("GEMINI_API_KEY");
        }
        if (key == null || key.isBlank()) {
            key = System.getenv("WEBSHIELD_LLM_API_KEY");
        }
        if (key == null || key.isBlank()) {
            key = System.getenv("OPENAI_API_KEY");
        }
        if (key == null || key.isBlank()) {
            key = CONFIGURED_FALLBACK_KEY;
        }

        String endpoint = System.getenv("WEBSHIELD_LLM_ENDPOINT");
        String model = System.getenv("WEBSHIELD_LLM_MODEL");
        String provider = System.getenv("WEBSHIELD_LLM_PROVIDER");

        boolean isKeyPresent = key != null && !key.isBlank();
        String activeProvider = (provider != null && !provider.isBlank()) ? provider : (isKeyPresent ? "gemini" : "mock");
        String activeModel = (model != null && !model.isBlank()) ? model : DEFAULT_MODEL;
        String activeEndpoint = (endpoint != null && !endpoint.isBlank()) ? endpoint : DEFAULT_ENDPOINT;

        return new LlmConfiguration(
                isKeyPresent,
                activeProvider,
                activeEndpoint,
                isKeyPresent ? key : "",
                activeModel,
                0.2,
                8192,
                DEFAULT_TIMEOUT,
                true // Enabled for verified reports
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
