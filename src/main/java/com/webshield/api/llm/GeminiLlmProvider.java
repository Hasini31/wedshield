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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Native Google Gemini LLM Provider integrating with Google AI Studio (Generative Language API v1beta).
 * Supports modern models including gemini-1.5-flash, gemini-2.0-flash, and gemini-1.5-pro.
 * Enforces strict error handling with descriptive exceptions and no silent mock fallback.
 */
public class GeminiLlmProvider implements LlmProvider {

    private static final Logger log = LoggerFactory.getLogger(GeminiLlmProvider.class);

    public static final String DEFAULT_GEMINI_MODEL = "gemini-3.1-flash-lite";
    public static final List<String> ACTIVE_CANDIDATE_MODELS = List.of(
            "gemini-3.1-flash-lite",
            "gemini-3.5-flash-lite",
            "gemini-3-flash-preview"
    );
    private static final String GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models/";

    private volatile HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public GeminiLlmProvider() {
        this(null, new ObjectMapper());
    }

    public GeminiLlmProvider(HttpClient httpClient, ObjectMapper objectMapper) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
    }

    private HttpClient getClient() {
        if (this.httpClient == null) {
            synchronized (this) {
                if (this.httpClient == null) {
                    this.httpClient = HttpClient.newBuilder()
                            .connectTimeout(Duration.ofSeconds(15))
                            .build();
                }
            }
        }
        return this.httpClient;
    }

    @Override
    public LlmResponse generateExplanation(LlmRequest request, LlmConfiguration config) throws LlmException {
        if (!isAvailable(config)) {
            throw new LlmException(
                    "Gemini API key is not configured. Please set the GEMINI_API_KEY environment variable.",
                    getProviderName(), null, false
            );
        }

        long start = System.currentTimeMillis();
        String primaryModel = resolveModel(config);
        String apiKey = config.apiKey().trim();

        List<String> modelsToTry = new ArrayList<>();
        modelsToTry.add(primaryModel);
        for (String m : ACTIVE_CANDIDATE_MODELS) {
            if (!modelsToTry.contains(m)) modelsToTry.add(m);
        }

        String lastError = null;
        int lastCode = 0;

        for (String model : modelsToTry) {
            try {
                String systemInstruction = request.systemPrompt();
                String userPrompt = request.prompt();

                String requestJson = buildGeminiRequestBody(systemInstruction, userPrompt, config.temperature(), config.maxTokens(), true);
                String url = GEMINI_API_BASE + model + ":generateContent?key=" + apiKey;

                HttpRequest httpRequest = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .timeout(Duration.ofSeconds(15))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(requestJson))
                        .build();

                HttpResponse<String> response = getClient().send(httpRequest, HttpResponse.BodyHandlers.ofString());
                long elapsed = System.currentTimeMillis() - start;

                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    JsonNode root = objectMapper.readTree(response.body());
                    String content = extractTextFromGeminiResponse(root);
                    int tokens = 0;
                    if (root.has("usageMetadata") && root.get("usageMetadata").has("totalTokenCount")) {
                        tokens = root.get("usageMetadata").get("totalTokenCount").asInt();
                    }
                    log.info("Gemini explanation successfully generated with model '{}' in {} ms ({} tokens)", model, elapsed, tokens);
                    return LlmResponse.successful(content, model, tokens, elapsed);
                } else {
                    lastCode = response.statusCode();
                    lastError = extractGeminiErrorMessage(response.statusCode(), response.body());
                    log.warn("Gemini model '{}' returned HTTP {}: {}. Attempting candidate model if available...", model, response.statusCode(), lastError);
                    if (response.statusCode() != 404 && response.statusCode() != 503) {
                        throw new LlmException("Google Gemini API Error (" + response.statusCode() + "): " + lastError, getProviderName(), null, response.statusCode() == 429);
                    }
                }
            } catch (LlmException e) {
                throw e;
            } catch (Exception e) {
                lastError = e.getMessage();
                log.warn("Gemini model '{}' request exception: {}. Trying candidate model...", model, e.getMessage());
            }
        }

        throw new LlmException("Google Gemini API Error (" + lastCode + "): " + lastError, getProviderName(), null, lastCode == 429);
    }

    /**
     * Generates a complete comprehensive security assessment report from structured scan data.
     *
     * @param systemInstruction Persona, rules, and mandatory 10-section format instructions
     * @param scanDataJson      Structured scan data and findings
     * @param config            LLM configuration
     * @return Generated full report text
     * @throws LlmException on API error, timeout, or missing key
     */
    public String generateCompleteReport(String systemInstruction, String scanDataJson, LlmConfiguration config) throws LlmException {
        if (!isAvailable(config)) {
            throw new LlmException(
                    "Gemini API key is not configured. Please set the GEMINI_API_KEY environment variable.",
                    getProviderName(), null, false
            );
        }

        long start = System.currentTimeMillis();
        String primaryModel = resolveModel(config);
        String apiKey = config.apiKey().trim();

        List<String> modelsToTry = new ArrayList<>();
        modelsToTry.add(primaryModel);
        for (String m : ACTIVE_CANDIDATE_MODELS) {
            if (!modelsToTry.contains(m)) modelsToTry.add(m);
        }

        String lastError = null;
        int lastCode = 0;

        for (String model : modelsToTry) {
            try {
                String requestJson = buildGeminiRequestBody(systemInstruction, scanDataJson, 0.2, 8192, false);
                String url = GEMINI_API_BASE + model + ":generateContent?key=" + apiKey;

                HttpRequest httpRequest = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .timeout(Duration.ofSeconds(120)) // 2 minutes for complete document generation
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(requestJson))
                        .build();

                HttpResponse<String> response = getClient().send(httpRequest, HttpResponse.BodyHandlers.ofString());
                long elapsed = System.currentTimeMillis() - start;

                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    JsonNode root = objectMapper.readTree(response.body());
                    String reportText = extractTextFromGeminiResponse(root);
                    log.info("Gemini full report successfully generated using model '{}' in {} ms ({} characters)", model, elapsed, reportText.length());
                    return reportText;
                } else {
                    lastCode = response.statusCode();
                    lastError = extractGeminiErrorMessage(response.statusCode(), response.body());
                    log.warn("Gemini model '{}' error HTTP {}: {}. Attempting candidate model if available...", model, response.statusCode(), lastError);
                    if (response.statusCode() != 404 && response.statusCode() != 503) {
                        throw new LlmException("Google Gemini API Error (" + response.statusCode() + "): " + lastError, getProviderName(), null, response.statusCode() == 429);
                    }
                }
            } catch (LlmException e) {
                throw e;
            } catch (Exception e) {
                lastError = e.getMessage();
                log.warn("Gemini report generation failed with model '{}': {}. Trying candidate model...", model, e.getMessage());
            }
        }

        throw new LlmException("Google Gemini API Error (" + lastCode + "): " + lastError, getProviderName(), null, lastCode == 429);
    }

    private String buildGeminiRequestBody(String systemInstruction, String userPrompt, double temperature, int maxTokens, boolean forceJson) {
        StringBuilder sb = new StringBuilder("{");

        // systemInstruction
        if (systemInstruction != null && !systemInstruction.isBlank()) {
            sb.append("\"systemInstruction\":{\"parts\":[{\"text\":")
              .append(escapeJson(systemInstruction))
              .append("}]},");
        }

        // contents
        sb.append("\"contents\":[{\"parts\":[{\"text\":")
          .append(escapeJson(userPrompt))
          .append("}]}],");

        // generationConfig
        sb.append("\"generationConfig\":{")
          .append("\"temperature\":").append(String.format(java.util.Locale.US, "%.2f", temperature)).append(",")
          .append("\"maxOutputTokens\":").append(maxTokens);

        if (forceJson) {
            sb.append(",\"responseMimeType\":\"application/json\"");
        }

        sb.append("}}");
        return sb.toString();
    }

    private String extractTextFromGeminiResponse(JsonNode root) throws LlmException {
        if (root.has("candidates") && root.get("candidates").isArray() && !root.get("candidates").isEmpty()) {
            JsonNode candidate = root.get("candidates").get(0);
            if (candidate.has("content") && candidate.get("content").has("parts") && candidate.get("content").get("parts").isArray()) {
                StringBuilder text = new StringBuilder();
                for (JsonNode part : candidate.get("content").get("parts")) {
                    if (part.has("text")) {
                        text.append(part.get("text").asText());
                    }
                }
                if (!text.isEmpty()) {
                    return text.toString();
                }
            }
            if (candidate.has("finishReason")) {
                String finishReason = candidate.get("finishReason").asText();
                if (!"STOP".equalsIgnoreCase(finishReason)) {
                    log.warn("Gemini candidate finish reason: {}", finishReason);
                }
            }
        }
        throw new LlmException("Gemini returned an empty or unparseable response structure.", getProviderName(), null, false);
    }

    private String extractGeminiErrorMessage(int statusCode, String responseBody) {
        try {
            JsonNode root = objectMapper.readTree(responseBody);
            if (root.has("error") && root.get("error").has("message")) {
                return root.get("error").get("message").asText();
            }
        } catch (Exception ignored) {}

        if (statusCode == 400) return "Bad request or invalid API key. Please verify your GEMINI_API_KEY.";
        if (statusCode == 403) return "Access denied. Ensure your Google AI Studio Gemini API key is valid and active.";
        if (statusCode == 429) return "Gemini API rate limit or quota exceeded. Please wait a moment and try again.";
        return responseBody != null && !responseBody.isBlank() ? responseBody : "Unknown Gemini API error (" + statusCode + ")";
    }

    private String resolveModel(LlmConfiguration config) {
        if (config != null && config.modelName() != null && !config.modelName().isBlank()
                && !config.modelName().equalsIgnoreCase("gpt-4o-mini")
                && !config.modelName().equalsIgnoreCase("mock")
                && !config.modelName().equalsIgnoreCase("gemini-1.5-flash")
                && !config.modelName().equalsIgnoreCase("gemini-1.5-pro")
                && !config.modelName().equalsIgnoreCase("gemini-2.0-flash")
                && !config.modelName().equalsIgnoreCase("gemini-2.5-flash")) {
            return config.modelName().trim();
        }
        return DEFAULT_GEMINI_MODEL;
    }

    private String escapeJson(String s) {
        if (s == null) return "\"\"";
        try {
            return objectMapper.writeValueAsString(s);
        } catch (Exception e) {
            return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\"";
        }
    }

    @Override
    public boolean isAvailable(LlmConfiguration config) {
        if (config == null || !config.enabled()) return false;
        return config.apiKey() != null && !config.apiKey().isBlank();
    }

    @Override
    public String getProviderName() {
        return "gemini";
    }
}
