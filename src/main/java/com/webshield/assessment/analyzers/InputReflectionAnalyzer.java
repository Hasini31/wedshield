package com.webshield.assessment.analyzers;

import com.webshield.assessment.AssessmentContext;
import com.webshield.assessment.AssessmentRule;
import com.webshield.assessment.models.AssessmentResult;
import com.webshield.assessment.models.ConfidenceLevel;
import com.webshield.assessment.models.Severity;
import com.webshield.crawler.DiscoveredField;
import com.webshield.crawler.DiscoveredForm;
import com.webshield.crawler.DiscoveredPage;
import com.webshield.crawler.ParameterExtractor;
import com.webshield.http.HttpRequestBuilder;
import com.webshield.http.HttpRequestData;
import com.webshield.http.HttpResponseData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.springframework.stereotype.Component;

/**
 * Analyzes whether input parameters are reflected unescaped in server responses.
 * Uses unique, non-destructive alphanumeric canary markers.
 * Reference: OWASP ZAP ReflectedXSSScanner.
 */
@Component
public class InputReflectionAnalyzer implements AssessmentRule {

    private static final Logger log = LoggerFactory.getLogger(InputReflectionAnalyzer.class);
    private final ParameterExtractor paramExtractor = new ParameterExtractor();

    @Override
    public String getRuleId() { return "WS-RULE-REFLECTION"; }

    @Override
    public String getName() { return "Input Reflection Analysis"; }

    @Override
    public String getCategory() { return "Input Handling"; }

    @Override
    public List<AssessmentResult> analyze(AssessmentContext context, DiscoveredPage page, HttpResponseData response) {
        // Passive analysis: check if existing query parameter values are directly echoed
        List<AssessmentResult> results = new ArrayList<>();
        if (response == null || page.getUrl() == null) {
            return results;
        }

        Map<String, List<String>> queryParams = paramExtractor.extractQueryParameters(page.getUrl());
        String body = response.getBody();

        for (Map.Entry<String, List<String>> entry : queryParams.entrySet()) {
            String paramName = entry.getKey();
            for (String val : entry.getValue()) {
                if (val != null && val.length() >= 3 && body.contains(val)) {
                    // Note passive observation with informational severity
                    results.add(new AssessmentResult(
                            "Passive Query Parameter Reflection",
                            "Input Handling",
                            "WS-REF-001",
                            page.getUrl(),
                            paramName,
                            page.getHttpMethod(),
                            Severity.INFORMATIONAL,
                            ConfidenceLevel.INFORMATIONAL,
                            "The query parameter '" + paramName + "' with value '" + val + "' was passively observed reflected in the HTTP response body.",
                            "Parameter: " + paramName + ", Reflected Value: " + val,
                            "Passive Reflection Observation",
                            "Ensure user-controlled data is contextually HTML-entity encoded before being rendered."
                    ));
                }
            }
        }

        return results;
    }

    @Override
    public List<AssessmentResult> probe(AssessmentContext context, DiscoveredPage page) {
        List<AssessmentResult> results = new ArrayList<>();
        if (context.isCancelled() || page.getUrl() == null) {
            return results;
        }

        String targetDomain = context.getWebsite().getUrl();

        // 1. Probe query parameters with safe canary token
        Map<String, List<String>> queryParams = paramExtractor.extractQueryParameters(page.getUrl());
        for (String param : queryParams.keySet()) {
            if (context.isCancelled()) break;

            String canary = "ws_probe_" + UUID.randomUUID().toString().substring(0, 8);
            String probeUrl = replaceQueryParam(page.getUrl(), param, canary);

            try {
                HttpRequestData req = HttpRequestBuilder.get(probeUrl).timeout(10).build();
                HttpResponseData res = context.getHttpManager().execute(req, targetDomain);

                if (res.getBody().contains(canary)) {
                    // Extract snippet around canary
                    String excerpt = extractSnippet(res.getBody(), canary);
                    results.add(new AssessmentResult(
                            "Potential Input Reflection",
                            "Input Handling",
                            "WS-REF-001",
                            page.getUrl(),
                            param,
                            "GET",
                            Severity.HIGH,
                            ConfidenceLevel.POTENTIAL,
                            "User input supplied to parameter '" + param + "' was reflected back in the HTTP response without apparent encoding. This indicates potential susceptibility to Cross-Site Scripting (XSS).",
                            "Canary: " + canary + " | Context snippet: " + excerpt,
                            "Canary Injection Probe",
                            "Apply context-aware output encoding (HTML, attribute, JavaScript, or URL encoding) for all reflected user data."
                    ));
                }
            } catch (Exception e) {
                log.debug("Reflection probe failed on {}: {}", probeUrl, e.getMessage());
            }
        }

        return results;
    }

    private String replaceQueryParam(String url, String paramName, String newValue) {
        try {
            URI uri = new URI(url);
            String rawQuery = uri.getRawQuery();
            if (rawQuery == null) return url;

            String encodedVal = URLEncoder.encode(newValue, StandardCharsets.UTF_8);
            StringBuilder sb = new StringBuilder();

            String[] pairs = rawQuery.split("&");
            for (String pair : pairs) {
                if (!sb.isEmpty()) sb.append("&");
                int idx = pair.indexOf("=");
                String key = idx > 0 ? pair.substring(0, idx) : pair;
                if (key.equalsIgnoreCase(paramName)) {
                    sb.append(key).append("=").append(encodedVal);
                } else {
                    sb.append(pair);
                }
            }

            URI newUri = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(),
                    uri.getPort(), uri.getPath(), sb.toString(), null);
            return newUri.toString();
        } catch (Exception e) {
            return url;
        }
    }

    private String extractSnippet(String content, String match) {
        int idx = content.indexOf(match);
        if (idx < 0) return "";
        int start = Math.max(0, idx - 40);
        int end = Math.min(content.length(), idx + match.length() + 40);
        return content.substring(start, end).replaceAll("\\s+", " ").trim();
    }
}

