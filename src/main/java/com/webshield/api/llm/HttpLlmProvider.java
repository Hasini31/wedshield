package com.webshield.api.llm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * HTTP REST LLM provider using native Java 21 {@link HttpClient}.
 * Supports OpenAI-compatible endpoints (OpenAI, Ollama, LM-Studio, LocalAI, vLLM, Gemini REST).
 */
public class HttpLlmProvider implements LlmProvider {

    private static final Logger log = LoggerFactory.getLogger(HttpLlmProvider.class);

    private volatile HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public HttpLlmProvider() {
        this(null, new ObjectMapper());
    }

    public HttpLlmProvider(HttpClient httpClient, ObjectMapper objectMapper) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
    }

    private HttpClient getClient() {
        if (this.httpClient == null) {
            synchronized (this) {
                if (this.httpClient == null) {
                    this.httpClient = HttpClient.newBuilder()
                            .connectTimeout(Duration.ofSeconds(10))
                            .build();
                }
            }
        }
        return this.httpClient;
    }

    @Override
    public LlmResponse generateExplanation(LlmRequest request, LlmConfiguration config) throws LlmException {
        if (!isAvailable(config)) {
            throw new LlmException("HTTP LLM provider is not configured with an endpoint URL or API key", getProviderName(), null, false);
        }

        long start = System.currentTimeMillis();
        try {
            List<Map<String, String>> messages = List.of(
                    Map.of("role", "system", "content", request.systemPrompt()),
                    Map.of("role", "user", "content", request.prompt())
            );

            Map<String, Object> payload = Map.of(
                    "model", config.modelName(),
                    "messages", messages,
                    "temperature", config.temperature(),
                    "max_tokens", config.maxTokens()
            );

            String requestBodyJson = objectMapper.writeValueAsString(payload);

            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(config.endpointUrl()))
                    .timeout(config.timeout())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBodyJson));

            if (config.apiKey() != null && !config.apiKey().isBlank()) {
                reqBuilder.header("Authorization", "Bearer " + config.apiKey().trim());
            }

            HttpResponse<String> response = getClient().send(reqBuilder.build(), HttpResponse.BodyHandlers.ofString());
            long elapsed = System.currentTimeMillis() - start;

            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                JsonNode root = objectMapper.readTree(response.body());
                String content = extractContentFromOpenAiFormat(root);
                int tokens = root.has("usage") && root.get("usage").has("total_tokens")
                        ? root.get("usage").get("total_tokens").asInt() : 0;
                return LlmResponse.successful(content, config.modelName(), tokens, elapsed);
            } else {
                String errMsg = "LLM provider HTTP " + response.statusCode() + ": " + response.body();
                log.warn("LLM endpoint error: {}", errMsg);
                return LlmResponse.failed(errMsg, config.modelName(), elapsed);
            }
        } catch (java.net.http.HttpTimeoutException e) {
            long elapsed = System.currentTimeMillis() - start;
            log.error("LLM request timed out after {} ms", elapsed);
            throw new LlmException("LLM request timed out after " + config.timeout().toSeconds() + "s", getProviderName(), e, true);
        } catch (Exception e) {
            long elapsed = System.currentTimeMillis() - start;
            log.error("LLM request dispatch failed: {}", e.getMessage());
            throw new LlmException("Failed to communicate with LLM provider: " + e.getMessage(), getProviderName(), e, false);
        }
    }

    private String extractContentFromOpenAiFormat(JsonNode root) {
        if (root.has("choices") && root.get("choices").isArray() && !root.get("choices").isEmpty()) {
            JsonNode firstChoice = root.get("choices").get(0);
            if (firstChoice.has("message") && firstChoice.get("message").has("content")) {
                return firstChoice.get("message").get("content").asText();
            }
        }
        // Fallback for simple direct content
        if (root.has("content")) {
            return root.get("content").asText();
        }
        return root.toString();
    }

    @Override
    public boolean isAvailable(LlmConfiguration config) {
        if (config == null || !config.enabled()) return false;
        if (config.endpointUrl() == null || config.endpointUrl().isBlank()) return false;
        // Local Ollama endpoints do not require an API key; public cloud endpoints typically do
        boolean isLocal = config.endpointUrl().contains("localhost") || config.endpointUrl().contains("127.0.0.1");
        return isLocal || (config.apiKey() != null && !config.apiKey().isBlank());
    }

    @Override
    public String getProviderName() {
        return "openai-http";
    }
}
