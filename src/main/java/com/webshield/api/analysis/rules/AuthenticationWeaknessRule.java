package com.webshield.api.analysis.rules;

import com.webshield.api.analysis.ApiFindingConfidence;
import com.webshield.api.analysis.ApiFindingSeverity;
import com.webshield.api.analysis.ApiSecurityFinding;
import com.webshield.api.analysis.ApiSecurityRule;
import com.webshield.api.analysis.CweMapping;
import com.webshield.api.analysis.OwaspApiCategory;
import com.webshield.api.analysis.RedactionUtils;
import com.webshield.api.execution.ApiExecutionRequest;
import com.webshield.api.execution.ApiExecutionResponse;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Identifies authentication weaknesses including unprotected sensitive endpoints,
 * inconsistent HTTP status codes on authentication failures (200 OK with error body),
 * and transmitting credentials via GET query parameters.
 */
@Component
public class AuthenticationWeaknessRule implements ApiSecurityRule {

    public static final String RULE_ID = "RULE-AUTH-WEAKNESS";

    private static final Pattern AUTH_ERROR_BODY_PATTERN = Pattern.compile(
            "(?i)\"(?:error|status|message)\"\\s*:\\s*\"?(?:unauthorized|access[ _-]?denied|unauthenticated|forbidden|invalid[ _-]?token|authentication[ _-]?required|401|403)\"?");

    private static final List<String> SENSITIVE_PARAM_NAMES = List.of(
            "token", "access_token", "auth_token", "apikey", "api_key", "secret", "password", "pwd", "bearer");

    private static final List<String> PROTECTED_PATH_PREFIXES = List.of(
            "/admin", "/user/profile", "/api/profile", "/api/users", "/api/accounts", "/api/orders", "/secure/", "/api/internal");

    @Override
    public String getRuleId() {
        return RULE_ID;
    }

    @Override
    public String getName() {
        return "Authentication Weakness Detection";
    }

    @Override
    public String getDescription() {
        return "Detects unauthenticated access to protected endpoints, inconsistent 200 OK authentication error responses, and credentials in URLs.";
    }

    @Override
    public ApiFindingSeverity getSeverity() {
        return ApiFindingSeverity.HIGH;
    }

    @Override
    public OwaspApiCategory getOwaspCategory() {
        return OwaspApiCategory.API2_BROKEN_AUTH;
    }

    @Override
    public String getCweId() {
        return CweMapping.CWE_287;
    }

    @Override
    public String getRemediation() {
        return "Enforce robust authentication on all sensitive endpoints, return standard 401 Unauthorized or 403 Forbidden HTTP status codes on auth failures, and transmit credentials exclusively in HTTP headers or request bodies.";
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

        // 1. Credentials in URL Query String
        if (request != null && request.queryParameters() != null) {
            for (String param : request.queryParameters().keySet()) {
                String lowerParam = param.toLowerCase(Locale.ROOT);
                if (SENSITIVE_PARAM_NAMES.stream().anyMatch(lowerParam::contains)) {
                    Object val = request.queryParameters().get(param);
                    String rawEvidence = param + "=" + (val != null ? val : "");
                    String safeEvidence = RedactionUtils.redactSensitiveData(rawEvidence);

                    findings.add(ApiSecurityFinding.builder()
                            .ruleId(RULE_ID)
                            .title("Authentication Weakness: Sensitive Credential Transmitted in URL Query String")
                            .description("Sensitive authentication parameter '" + param + "' was submitted via the URL query string.")
                            .severity(ApiFindingSeverity.MEDIUM)
                            .confidence(ApiFindingConfidence.HIGH)
                            .apiProjectId(projectId)
                            .httpMethod(method)
                            .endpointPath(path)
                            .parameterOrField(param)
                            .evidence(safeEvidence)
                            .cweId(CweMapping.CWE_598)
                            .owaspCategory(OwaspApiCategory.API2_BROKEN_AUTH)
                            .remediation("Never send authentication tokens or credentials in URL parameters. Pass tokens via the 'Authorization: Bearer' header.")
                            .executionId(executionId)
                            .isConfirmed(true)
                            .build());
                }
            }
        }

        // 2. Inconsistent Authentication Failure Status (200 OK with Auth Failure Body)
        if (response.statusCode() == 200 && response.responseBody() != null && !response.responseBody().isBlank()) {
            if (AUTH_ERROR_BODY_PATTERN.matcher(response.responseBody()).find()) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Authentication Weakness: Inconsistent 200 OK Status on Authentication Failure")
                        .description("The API returned HTTP 200 OK while the response body indicates an authentication or authorization failure.")
                        .severity(ApiFindingSeverity.MEDIUM)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("status")
                        .evidence("HTTP 200 OK with body: " + RedactionUtils.redactSensitiveData(truncateBody(response.responseBody())))
                        .cweId(CweMapping.CWE_287)
                        .owaspCategory(OwaspApiCategory.API2_BROKEN_AUTH)
                        .remediation("Return standard HTTP status codes: 401 Unauthorized for unauthenticated requests and 403 Forbidden for insufficient permissions.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }
        }

        // 3. Protected Endpoint Returning 200 OK Without Authentication
        if (response.is2xxSuccess() && request != null) {
            boolean hasAuthHeader = hasAuthHeader(request.headers());
            boolean explicitUnauth = Boolean.TRUE.equals(request.metadata().get("unauthenticated"))
                    || Boolean.TRUE.equals(request.metadata().get("authExpected"));

            boolean looksProtected = PROTECTED_PATH_PREFIXES.stream().anyMatch(prefix -> path.toLowerCase().startsWith(prefix));

            if (!hasAuthHeader && (explicitUnauth || looksProtected)) {
                // Ensure the body actually returned data rather than empty 204 or public splash
                if (response.responseBody() != null && response.responseBody().trim().length() > 2) {
                    findings.add(ApiSecurityFinding.builder()
                            .ruleId(RULE_ID)
                            .title("Authentication Weakness: Protected Endpoint Accessible Without Authentication")
                            .description("Endpoint '" + path + "' returned HTTP 200 OK without valid authentication credentials.")
                            .severity(ApiFindingSeverity.HIGH)
                            .confidence(explicitUnauth ? ApiFindingConfidence.HIGH : ApiFindingConfidence.MEDIUM)
                            .apiProjectId(projectId)
                            .httpMethod(method)
                            .endpointPath(path)
                            .parameterOrField("Authorization")
                            .evidence("HTTP " + response.statusCode() + " OK without Authorization header")
                            .cweId(CweMapping.CWE_287)
                            .owaspCategory(OwaspApiCategory.API2_BROKEN_AUTH)
                            .remediation("Enforce authentication checks at the API gateway or controller layer using Spring Security or interceptors.")
                            .executionId(executionId)
                            .isConfirmed(explicitUnauth)
                            .build());
                }
            }
        }

        return findings;
    }

    private static boolean hasAuthHeader(Map<String, String> headers) {
        if (headers == null) return false;
        for (String k : headers.keySet()) {
            if ("authorization".equalsIgnoreCase(k) || "x-api-key".equalsIgnoreCase(k) || "cookie".equalsIgnoreCase(k)) {
                String val = headers.get(k);
                if (val != null && !val.isBlank()) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String truncateBody(String body) {
        if (body.length() > 200) {
            return body.substring(0, 197) + "...";
        }
        return body;
    }
}

