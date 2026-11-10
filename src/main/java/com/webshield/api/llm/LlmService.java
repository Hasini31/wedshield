package com.webshield.api.llm;

import com.webshield.api.dto.ApiFindingDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Main service orchestrating LLM finding explanations, prompt redaction, user consent enforcement,
 * validation, and fallback mechanisms.
 */
@Service
public class LlmService {

    private static final Logger log = LoggerFactory.getLogger(LlmService.class);

    private final Map<String, LlmProvider> providers = new ConcurrentHashMap<>();
    private final LlmPromptBuilder promptBuilder;
    private final LlmResponseValidator responseValidator;
    private final Map<Long, LlmFindingExplanation> explanationCache = new ConcurrentHashMap<>();

    private volatile LlmConfiguration currentConfiguration;

    public LlmService() {
        this(new LlmPromptBuilder(), new LlmResponseValidator(), LlmConfiguration.fromEnvironment());
    }

    public LlmService(LlmPromptBuilder promptBuilder, LlmResponseValidator responseValidator, LlmConfiguration configuration) {
        this.promptBuilder = promptBuilder != null ? promptBuilder : new LlmPromptBuilder();
        this.responseValidator = responseValidator != null ? responseValidator : new LlmResponseValidator();
        this.currentConfiguration = configuration != null ? configuration : LlmConfiguration.fromEnvironment();

        // Register default providers
        registerProvider(new MockLlmProvider());
        registerProvider(new HttpLlmProvider());
    }

    public void registerProvider(LlmProvider provider) {
        if (provider != null) {
            providers.put(provider.getProviderName().toLowerCase(), provider);
            log.info("Registered LLM Provider: '{}'", provider.getProviderName());
        }
    }

    public LlmConfiguration getConfiguration() {
        return currentConfiguration;
    }

    public void setConfiguration(LlmConfiguration configuration) {
        if (configuration != null) {
            this.currentConfiguration = configuration;
        }
    }

    /**
     * Explains a single security finding with user consent verification and provider fallback.
     */
    public LlmFindingExplanation explainFinding(ApiFindingDto finding, boolean userConsent) {
        if (finding == null) {
            throw new IllegalArgumentException("Finding must not be null");
        }

        // Return cached explanation if present
        if (finding.id() != null && explanationCache.containsKey(finding.id())) {
            return explanationCache.get(finding.id());
        }

        // Section 5 Requirement: User-controlled consent before sending data externally
        if (!userConsent) {
            log.info("External sharing consent not granted for finding #{}; returning local advisory template.", finding.id());
            return responseValidator.fallbackExplanation(
                    finding.id(),
                    finding.title(),
                    "External transmission disabled by user consent settings",
                    "Local-Defensive-Policy"
            );
        }

        LlmProvider provider = resolveActiveProvider();
        if (provider == null || !provider.isAvailable(currentConfiguration)) {
            log.info("Configured LLM provider '{}' not available; using fallback mock.", currentConfiguration.providerName());
            provider = providers.getOrDefault("mock", new MockLlmProvider());
        }

        try {
            LlmRequest request = promptBuilder.buildFindingExplanationRequest(finding);
            LlmResponse response = provider.generateExplanation(request, currentConfiguration);

            LlmFindingExplanation explanation;
            if (response != null && response.success()) {
                explanation = responseValidator.validateAndMap(
                        finding.id(),
                        finding.title(),
                        response.rawContent(),
                        provider.getProviderName()
                );
            } else {
                String err = response != null ? response.errorMessage() : "Empty response";
                explanation = responseValidator.fallbackExplanation(finding.id(), finding.title(), err, provider.getProviderName());
            }

            if (finding.id() != null) {
                explanationCache.put(finding.id(), explanation);
            }
            return explanation;
        } catch (Exception e) {
            log.warn("LLM explanation dispatch failed for finding #{}: {}", finding.id(), e.getMessage());
            LlmFindingExplanation fallback = responseValidator.fallbackExplanation(
                    finding.id(),
                    finding.title(),
                    "Provider error: " + e.getMessage(),
                    provider.getProviderName()
            );
            if (finding.id() != null) {
                explanationCache.put(finding.id(), fallback);
            }
            return fallback;
        }
    }

    /**
     * Enriches a batch of findings with AI explanations.
     */
    public Map<Long, LlmFindingExplanation> enrichFindings(List<ApiFindingDto> findings, boolean userConsent) {
        if (findings == null || findings.isEmpty()) {
            return Collections.emptyMap();
        }

        Map<Long, LlmFindingExplanation> results = new LinkedHashMap<>();
        for (ApiFindingDto f : findings) {
            if (f != null && f.id() != null) {
                results.put(f.id(), explainFinding(f, userConsent));
            }
        }
        return results;
    }

    public void clearCache() {
        explanationCache.clear();
    }

    private LlmProvider resolveActiveProvider() {
        String name = currentConfiguration.providerName().toLowerCase();
        if (providers.containsKey(name)) {
            return providers.get(name);
        }
        if (name.contains("openai") || name.contains("http") || name.contains("ollama")) {
            return providers.get("openai-http");
        }
        return providers.get("mock");
    }
}

