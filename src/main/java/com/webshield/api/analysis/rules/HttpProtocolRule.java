package com.webshield.api.analysis.rules;

import com.webshield.api.analysis.ApiFindingConfidence;
import com.webshield.api.analysis.ApiFindingSeverity;
import com.webshield.api.analysis.ApiSecurityFinding;
import com.webshield.api.analysis.ApiSecurityRule;
import com.webshield.api.analysis.CweMapping;
import com.webshield.api.analysis.OwaspApiCategory;
import com.webshield.api.execution.ApiExecutionRequest;
import com.webshield.api.execution.ApiExecutionResponse;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Evaluates HTTP protocol compliance, MIME type fidelity, dangerous HTTP verbs,
 * and caching directives for sensitive resources.
 */
@Component
public class HttpProtocolRule implements ApiSecurityRule {

    public static final String RULE_ID = "RULE-HTTP-PROTOCOL";

    private static final List<String> SENSITIVE_CACHE_PATHS = List.of(
            "/login", "/token", "/auth", "/password", "/profile", "/account", "/credentials", "/session");

    @Override
    public String getRuleId() {
        return RULE_ID;
    }

    @Override
    public String getName() {
        return "HTTP Protocol and MIME Security Detection";
    }

    @Override
    public String getDescription() {
        return "Detects missing or mismatched Content-Type headers, insecure allowed HTTP methods (TRACE/TRACK), and unmitigated caching of sensitive endpoints.";
    }

    @Override
    public ApiFindingSeverity getSeverity() {
        return ApiFindingSeverity.LOW;
    }

    @Override
    public OwaspApiCategory getOwaspCategory() {
        return OwaspApiCategory.API8_SECURITY_MISCONFIGURATION;
    }

    @Override
    public String getCweId() {
        return CweMapping.CWE_16;
    }

    @Override
    public String getRemediation() {
        return "Specify accurate Content-Type headers, disable hazardous HTTP methods such as TRACE and TRACK, and apply 'Cache-Control: no-store' on authenticated or sensitive endpoints.";
    }

    @Override
    public List<ApiSecurityFinding> analyze(ApiExecutionRequest request, ApiExecutionResponse response) {
        List<ApiSecurityFinding> findings = new ArrayList<>();
        if (response == null || !response.connectionSuccessful()) {
            return findings;
        }

        String path = request != null ? request.resolvedPath() : "/";
        Long projectId = request != null ? request.apiProjectId() : null;
        var method = request != null ? request.method() : null;
        String executionId = response.executionId();
        String body = response.responseBody();
        String contentType = response.contentType();

        Map<String, List<String>> headers = response.responseHeaders();

        // 1. Missing or Unknown Content-Type on non-empty payload
        if (body != null && !body.isBlank()) {
            if (contentType == null || contentType.isBlank() || "unknown".equalsIgnoreCase(contentType.trim())) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("HTTP Protocol Issue: Missing or Unknown Content-Type Header")
                        .description("Response contains a non-empty payload but lacks an explicit, well-defined Content-Type header.")
                        .severity(ApiFindingSeverity.LOW)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("Content-Type")
                        .evidence("Missing Content-Type header on non-empty payload (" + response.responseSizeBytes() + " bytes)")
                        .cweId(CweMapping.CWE_16)
                        .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                        .remediation("Ensure all responses include an explicit Content-Type (e.g. application/json; charset=utf-8).")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            } else {
                // 2. Content-Type Mismatch
                String trimmedBody = body.trim();
                String lowerContentType = contentType.toLowerCase(Locale.ROOT);

                boolean looksLikeJson = (trimmedBody.startsWith("{") && trimmedBody.endsWith("}"))
                        || (trimmedBody.startsWith("[") && trimmedBody.endsWith("]"));

                boolean looksLikeHtml = trimmedBody.toLowerCase(Locale.ROOT).startsWith("<!doctype")
                        || trimmedBody.toLowerCase(Locale.ROOT).startsWith("<html");

                if (looksLikeJson && (lowerContentType.contains("text/html") || lowerContentType.contains("text/plain"))) {
                    findings.add(ApiSecurityFinding.builder()
                            .ruleId(RULE_ID)
                            .title("HTTP Protocol Issue: JSON Payload Served with Incompatible Content-Type")
                            .description("Response contains structured JSON payload but Content-Type is '" + contentType + "', which may trigger client MIME confusion or XSS.")
                            .severity(ApiFindingSeverity.LOW)
                            .confidence(ApiFindingConfidence.HIGH)
                            .apiProjectId(projectId)
                            .httpMethod(method)
                            .endpointPath(path)
                            .parameterOrField("Content-Type")
                            .evidence("Content-Type: " + contentType + " with JSON payload")
                            .cweId(CweMapping.CWE_16)
                            .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                            .remediation("Serve JSON responses with 'Content-Type: application/json; charset=utf-8'.")
                            .executionId(executionId)
                            .isConfirmed(true)
                            .build());
                } else if (looksLikeHtml && lowerContentType.contains("application/json")) {
                    findings.add(ApiSecurityFinding.builder()
                            .ruleId(RULE_ID)
                            .title("HTTP Protocol Issue: HTML Document Served as application/json")
                            .description("Response contains HTML markup but is labeled with Content-Type 'application/json'.")
                            .severity(ApiFindingSeverity.LOW)
                            .confidence(ApiFindingConfidence.HIGH)
                            .apiProjectId(projectId)
                            .httpMethod(method)
                            .endpointPath(path)
                            .parameterOrField("Content-Type")
                            .evidence("Content-Type: " + contentType + " with HTML document")
                            .cweId(CweMapping.CWE_16)
                            .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                            .remediation("Return standard JSON error structures rather than upstream HTML error pages.")
                            .executionId(executionId)
                            .isConfirmed(true)
                            .build());
                }
            }
        }

        // 3. Insecure HTTP Methods in Allow / Access-Control-Allow-Methods
        List<String> allowHeaders = getHeaderValues(headers, "Allow");
        if (allowHeaders.isEmpty()) {
            allowHeaders = getHeaderValues(headers, "Access-Control-Allow-Methods");
        }

        for (String allowVal : allowHeaders) {
            String upper = allowVal.toUpperCase(Locale.ROOT);
            if (upper.contains("TRACE") || upper.contains("TRACK")) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("HTTP Protocol Issue: Insecure TRACE/TRACK Method Enabled")
                        .description("Endpoint permits the TRACE or TRACK method, exposing the application to Cross-Site Tracing (XST) attacks.")
                        .severity(ApiFindingSeverity.MEDIUM)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("Allow")
                        .evidence("Allow header: " + allowVal)
                        .cweId(CweMapping.CWE_16)
                        .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                        .remediation("Disable HTTP TRACE and TRACK methods at the web server and proxy layers.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
                break;
            }
        }

        // 4. Sensitive Endpoint Missing Cache-Control
        if (response.is2xxSuccess() && SENSITIVE_CACHE_PATHS.stream().anyMatch(path.toLowerCase()::contains)) {
            List<String> cacheControls = getHeaderValues(headers, "Cache-Control");
            boolean hasNoStore = cacheControls.stream().anyMatch(v -> v.toLowerCase().contains("no-store") || v.toLowerCase().contains("no-cache"));

            if (!hasNoStore) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("HTTP Protocol Issue: Sensitive Endpoint Missing Cache-Control: no-store")
                        .description("Sensitive endpoint '" + path + "' does not specify 'Cache-Control: no-store', allowing intermediate proxies or browsers to cache sensitive data.")
                        .severity(ApiFindingSeverity.LOW)
                        .confidence(ApiFindingConfidence.MEDIUM)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("Cache-Control")
                        .evidence("Cache-Control header missing or permissive on " + path)
                        .cweId(CweMapping.CWE_524)
                        .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                        .remediation("Configure 'Cache-Control: no-store, no-cache, must-revalidate' on all authenticated or sensitive API responses.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }
        }

        return findings;
    }

    private static List<String> getHeaderValues(Map<String, List<String>> headers, String name) {
        List<String> result = new ArrayList<>();
        if (headers == null) return result;
        for (String k : headers.keySet()) {
            if (k.equalsIgnoreCase(name)) {
                List<String> vals = headers.get(k);
                if (vals != null) result.addAll(vals);
            }
        }
        return result;
    }
}

