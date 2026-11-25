package com.webshield.api.llm;

import com.webshield.api.dto.ApiFindingDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.*;

/**
 * Main service orchestrating LLM finding explanations, prompt redaction, user consent enforcement,
 * and Google Gemini AI Studio integration.
 */
@Service
public class LlmService {

    private static final Logger log = LoggerFactory.getLogger(LlmService.class);

    private final Map<String, LlmProvider> providers = new ConcurrentHashMap<>();
    private final LlmPromptBuilder promptBuilder;
    private final LlmResponseValidator responseValidator;
    private final Map<Long, LlmFindingExplanation> explanationCache = new ConcurrentHashMap<>();

    private volatile LlmConfiguration currentConfiguration;
    private final GeminiLlmProvider geminiProvider;

    public LlmService() {
        this(new LlmPromptBuilder(), new LlmResponseValidator(), LlmConfiguration.fromEnvironment());
    }

    public LlmService(LlmPromptBuilder promptBuilder, LlmResponseValidator responseValidator, LlmConfiguration configuration) {
        this.promptBuilder = promptBuilder != null ? promptBuilder : new LlmPromptBuilder();
        this.responseValidator = responseValidator != null ? responseValidator : new LlmResponseValidator();
        this.currentConfiguration = configuration != null ? configuration : LlmConfiguration.fromEnvironment();

        // Register providers: Gemini as primary, HTTP as alternative, Mock as fallback
        this.geminiProvider = new GeminiLlmProvider();
        registerProvider(this.geminiProvider);
        registerProvider(new HttpLlmProvider());
        registerProvider(new MockLlmProvider());
    }

    public void registerProvider(LlmProvider provider) {
        if (provider != null) {
            providers.put(provider.getProviderName().toLowerCase(), provider);
            log.info("Registered LLM Provider: '{}'", provider.getProviderName());
        }
    }

    public GeminiLlmProvider getGeminiProvider() {
        return geminiProvider;
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
     * Explains a single security finding with user consent verification and Gemini integration.
     * Enforces strict error reporting with no silent fallback to mock mode.
     */
    public LlmFindingExplanation explainFinding(ApiFindingDto finding, boolean userConsent) {
        if (finding == null) {
            throw new IllegalArgumentException("Finding must not be null");
        }

        // Return cached explanation if present
        if (finding.id() != null && explanationCache.containsKey(finding.id())) {
            return explanationCache.get(finding.id());
        }

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
            String errorMsg = "Configured LLM provider '" + currentConfiguration.providerName() +
                    "' is not available or missing GEMINI_API_KEY. Silent mock fallback is disabled.";
            log.error(errorMsg);
            return responseValidator.fallbackExplanation(
                    finding.id(),
                    finding.title(),
                    errorMsg,
                    currentConfiguration.providerName()
            );
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
                String err = response != null ? response.errorMessage() : "Empty response from Gemini API";
                explanation = responseValidator.fallbackExplanation(finding.id(), finding.title(), err, provider.getProviderName());
            }

            if (finding.id() != null) {
                explanationCache.put(finding.id(), explanation);
            }
            return explanation;
        } catch (Exception e) {
            log.error("LLM explanation dispatch failed for finding #{}: {}", finding.id(), e.getMessage());
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
     * Deduplicates findings by title and runs external LLM calls concurrently
     * to eliminate long sequential network latency.
     */
    public Map<Long, LlmFindingExplanation> enrichFindings(List<ApiFindingDto> findings, boolean userConsent) {
        if (findings == null || findings.isEmpty()) {
            return Collections.emptyMap();
        }

        if (!userConsent) {
            Map<Long, LlmFindingExplanation> results = new LinkedHashMap<>();
            for (ApiFindingDto f : findings) {
                if (f != null && f.id() != null) {
                    results.put(f.id(), explainFinding(f, false));
                }
            }
            return results;
        }

        // 1. Group findings by title to deduplicate external LLM requests
        Map<String, List<ApiFindingDto>> groupedByTitle = new LinkedHashMap<>();
        for (ApiFindingDto f : findings) {
            if (f != null && f.id() != null) {
                String key = f.title() != null ? f.title().trim() : "Unknown Finding";
                groupedByTitle.computeIfAbsent(key, k -> new ArrayList<>()).add(f);
            }
        }

        // 2. Sort unique titles by highest severity first (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        List<Map.Entry<String, List<ApiFindingDto>>> sortedGroups = new ArrayList<>(groupedByTitle.entrySet());
        sortedGroups.sort((a, b) -> {
            int sevA = getSeverityRank(a.getValue().get(0).severity());
            int sevB = getSeverityRank(b.getValue().get(0).severity());
            return Integer.compare(sevA, sevB);
        });

        // 3. Cap distinct external LLM calls to top 6 unique vulnerability types to respect rate limits
        final int MAX_DISTINCT_AI_CALLS = 6;
        Map<String, LlmFindingExplanation> titleExplanations = new ConcurrentHashMap<>();
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        int count = 0;

        for (Map.Entry<String, List<ApiFindingDto>> entry : sortedGroups) {
            String title = entry.getKey();
            ApiFindingDto representative = entry.getValue().get(0);

            if (count < MAX_DISTINCT_AI_CALLS) {
                count++;
                futures.add(CompletableFuture.runAsync(() -> {
                    try {
                        LlmFindingExplanation exp = explainFinding(representative, true);
                        titleExplanations.put(title, exp);
                    } catch (Exception e) {
                        log.warn("Failed to generate AI explanation for title '{}': {}", title, e.getMessage());
                        titleExplanations.put(title, responseValidator.fallbackExplanation(
                                representative.id(), title, "Explanation unavailable: " + e.getMessage(), "Local-Advisory"));
                    }
                }));
            } else {
                // Beyond cap, supply defensive guidance without external latency
                titleExplanations.put(title, responseValidator.fallbackExplanation(
                        representative.id(), title,
                        "Defensive hardening advisory based on OWASP security standards.", "WebShield-Policy"));
            }
        }

        // 4. Await parallel completion with max 25s timeout
        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .get(25, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.warn("Parallel AI finding enrichment timed out or interrupted: {}", e.getMessage());
        }

        // 5. Map explanations back to every finding ID and update cache
        Map<Long, LlmFindingExplanation> results = new LinkedHashMap<>();
        for (ApiFindingDto f : findings) {
            if (f == null || f.id() == null) continue;
            String key = f.title() != null ? f.title().trim() : "Unknown Finding";
            LlmFindingExplanation base = titleExplanations.get(key);
            if (base != null) {
                LlmFindingExplanation item;
                if (f.id().equals(base.findingId())) {
                    item = base;
                } else {
                    item = new LlmFindingExplanation(
                            f.id(),
                            f.title(),
                            base.summary(),
                            base.potentialImpact(),
                            base.exploitationScenario(),
                            base.remediationGuide(),
                            base.disclaimer(),
                            base.isAiAssisted(),
                            base.providerName(),
                            base.generatedAt()
                    );
                }
                explanationCache.put(f.id(), item);
                results.put(f.id(), item);
            } else {
                LlmFindingExplanation item = explainFinding(f, false);
                results.put(f.id(), item);
            }
        }

        return results;
    }

    private static int getSeverityRank(String severity) {
        if (severity == null) return 5;
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> 1;
            case "HIGH" -> 2;
            case "MEDIUM" -> 3;
            case "LOW" -> 4;
            default -> 5;
        };
    }

    public void clearCache() {
        explanationCache.clear();
    }

    private LlmProvider resolveActiveProvider() {
        String name = currentConfiguration.providerName().toLowerCase();
        if (providers.containsKey(name)) {
            return providers.get(name);
        }
        if (name.contains("gemini")) {
            return providers.get("gemini");
        }
        if (name.contains("openai") || name.contains("http") || name.contains("ollama")) {
            return providers.get("openai-http");
        }
        // Only return mock if explicitly requested
        if ("mock".equals(name)) {
            return providers.get("mock");
        }
        return providers.get("gemini");
    }
}
