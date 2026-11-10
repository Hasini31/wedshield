package com.webshield.api.llm;

import java.util.Map;

/**
 * Deterministic in-memory LLM provider for unit tests, offline execution, and development mode.
 */
public class MockLlmProvider implements LlmProvider {

    @Override
    public LlmResponse generateExplanation(LlmRequest request, LlmConfiguration config) throws LlmException {
        long start = System.currentTimeMillis();
        Map<String, String> ctx = request.findingContext();
        String title = ctx.getOrDefault("title", "Security Finding");
        String owasp = ctx.getOrDefault("owaspCategory", "API Security");
        String cwe = ctx.getOrDefault("cweId", "CWE-General");
        String endpoint = ctx.getOrDefault("endpoint", "Endpoint");

        String jsonResponse = String.format("""
                {
                  "summary": "The endpoint %s is susceptible to %s (%s). An external client can exploit this condition without sufficient server-side validation.",
                  "potentialImpact": "Unauthorized access, data exfiltration, or state modification compromising system integrity under %s.",
                  "exploitationScenario": "An attacker craftily dispatches a mutated request payload targeting %s, bypassing initial filters to observe unauthorized server side side-effects.",
                  "remediationGuide": "Implement strict input validation schemas, enforce principle of least privilege, and deploy automated boundary checks adhering to %s."
                }
                """, endpoint, title, cwe, owasp, endpoint, owasp);

        long elapsed = System.currentTimeMillis() - start;
        return LlmResponse.successful(jsonResponse, "mock-defensive-llm", 120, elapsed);
    }

    @Override
    public boolean isAvailable(LlmConfiguration config) {
        return true;
    }

    @Override
    public String getProviderName() {
        return "mock";
    }
}

