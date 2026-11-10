package com.webshield.api.llm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validates, cleanses, and maps raw LLM responses to structured {@link LlmFindingExplanation} records.
 */
public class LlmResponseValidator {

    private static final Logger log = LoggerFactory.getLogger(LlmResponseValidator.class);
    private final ObjectMapper objectMapper;

    public LlmResponseValidator() {
        this.objectMapper = new ObjectMapper();
    }

    public LlmResponseValidator(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
    }

    /**
     * Validates LLM response content and maps it to a structured explanation.
     */
    public LlmFindingExplanation validateAndMap(Long findingId, String findingTitle, String rawResponse, String providerName) {
        if (rawResponse == null || rawResponse.isBlank()) {
            return fallbackExplanation(findingId, findingTitle, "No content returned from LLM provider.", providerName);
        }

        String cleansed = cleanRawJson(rawResponse);
        try {
            JsonNode root = objectMapper.readTree(cleansed);

            String summary = extractText(root, "summary", "Summary not provided by AI assistant.");
            String potentialImpact = extractText(root, "potentialImpact", "Potential impact assessment not provided.");
            String exploitationScenario = extractText(root, "exploitationScenario", "Exploitation scenario not provided.");
            String remediationGuide = extractText(root, "remediationGuide", "Remediation guidance not provided.");

            // Sanitize against dangerous HTML tags if rendered in HTML report
            summary = sanitizeOutputText(summary);
            potentialImpact = sanitizeOutputText(potentialImpact);
            exploitationScenario = sanitizeOutputText(exploitationScenario);
            remediationGuide = sanitizeOutputText(remediationGuide);

            return LlmFindingExplanation.of(
                    findingId,
                    findingTitle,
                    summary,
                    potentialImpact,
                    exploitationScenario,
                    remediationGuide,
                    providerName
            );
        } catch (Exception e) {
            log.warn("Failed to parse LLM JSON response (falling back to sanitized plaintext): {}", e.getMessage());
            // If the LLM returned plain text instead of strict JSON, use it gracefully as summary
            String safeText = sanitizeOutputText(cleanRawJson(rawResponse));
            return LlmFindingExplanation.of(
                    findingId,
                    findingTitle,
                    safeText,
                    "Refer to official OWASP documentation for impact details.",
                    "Exploitation follows standard vector for this finding type.",
                    "Apply input validation, strict authorization, and secure configuration.",
                    providerName
            );
        }
    }

    public LlmFindingExplanation fallbackExplanation(Long findingId, String findingTitle, String reason, String providerName) {
        return LlmFindingExplanation.of(
                findingId,
                findingTitle,
                "AI-assisted explanation currently unavailable (" + reason + ").",
                "Refer to deterministic finding description and OWASP API Security guidelines.",
                "Exploitation scenario requires manual security review.",
                "Implement recommended baseline defensive controls.",
                providerName != null ? providerName : "Fallback"
        );
    }

    private String cleanRawJson(String raw) {
        String trimmed = raw.trim();
        if (trimmed.startsWith("```json")) {
            trimmed = trimmed.substring(7);
        } else if (trimmed.startsWith("```")) {
            trimmed = trimmed.substring(3);
        }
        if (trimmed.endsWith("```")) {
            trimmed = trimmed.substring(0, trimmed.length() - 3);
        }
        return trimmed.trim();
    }

    private String extractText(JsonNode node, String fieldName, String defaultValue) {
        if (node.hasNonNull(fieldName)) {
            String val = node.get(fieldName).asText();
            if (val != null && !val.isBlank()) {
                return val.trim();
            }
        }
        return defaultValue;
    }

    private String sanitizeOutputText(String input) {
        if (input == null) return "";
        // Strip out any potentially malicious HTML tags or script injection
        return input.replace("<script", "&lt;script")
                .replace("</script>", "&lt;/script&gt;")
                .replace("<iframe", "&lt;iframe")
                .replace("javascript:", "blocked-js:");
    }
}
