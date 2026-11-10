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
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Detects security misconfigurations including detailed server technology banners,
 * missing standard defensive HTTP headers, and debug modes left enabled in production.
 */
@Component
public class SecurityMisconfigurationRule implements ApiSecurityRule {

    public static final String RULE_ID = "RULE-SEC-MISCONFIG";

    private static final Pattern VERSION_PATTERN = Pattern.compile("\\d+\\.\\d+");

    private static final Pattern DEBUG_BODY_PATTERN = Pattern.compile(
            "(?i)\"(debug|debug_mode|development_mode)\"\\s*:\\s*(true|1)");

    @Override
    public String getRuleId() {
        return RULE_ID;
    }

    @Override
    public String getName() {
        return "Security Misconfiguration Detection";
    }

    @Override
    public String getDescription() {
        return "Detects server banner disclosures, missing defense-in-depth headers, and enabled debug flags.";
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
        return "Harden server configuration: suppress technology version headers, configure defense-in-depth security headers, and disable debug features in non-development environments.";
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
        Map<String, List<String>> headers = response.responseHeaders();

        // 1. Detailed Server / Technology Banners
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            String headerName = entry.getKey();
            List<String> values = entry.getValue();
            if (values == null || values.isEmpty()) continue;
            String headerVal = values.get(0);

            if ("server".equalsIgnoreCase(headerName)) {
                if (VERSION_PATTERN.matcher(headerVal).find()) {
                    findings.add(ApiSecurityFinding.builder()
                            .ruleId(RULE_ID)
                            .title("Security Misconfiguration: Server Banner Exposes Detailed Version")
                            .description("The Server response header discloses specific web server software and version numbers.")
                            .severity(ApiFindingSeverity.MEDIUM)
                            .confidence(ApiFindingConfidence.HIGH)
                            .apiProjectId(projectId)
                            .httpMethod(method)
                            .endpointPath(path)
                            .parameterOrField("Server")
                            .evidence("Server: " + headerVal)
                            .cweId(CweMapping.CWE_200)
                            .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                            .remediation("Configure the web server to suppress or tokenize the Server header (e.g., 'ServerTokens Prod' in Apache or 'server_tokens off;' in Nginx).")
                            .executionId(executionId)
                            .isConfirmed(true)
                            .build());
                }
            } else if ("x-powered-by".equalsIgnoreCase(headerName)) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Security Misconfiguration: Technology Framework Disclosed via X-Powered-By")
                        .description("The X-Powered-By header discloses underlying application framework information.")
                        .severity(ApiFindingSeverity.LOW)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("X-Powered-By")
                        .evidence("X-Powered-By: " + headerVal)
                        .cweId(CweMapping.CWE_200)
                        .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                        .remediation("Disable the X-Powered-By header in application server or reverse proxy configuration.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            } else if ("x-aspnet-version".equalsIgnoreCase(headerName) || "x-runtime".equalsIgnoreCase(headerName)) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Security Misconfiguration: Backend Runtime Version Disclosed")
                        .description("Response header '" + headerName + "' reveals internal framework details.")
                        .severity(ApiFindingSeverity.LOW)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField(headerName)
                        .evidence(headerName + ": " + headerVal)
                        .cweId(CweMapping.CWE_200)
                        .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                        .remediation("Remove verbose version headers from API responses.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            } else if (headerName.toLowerCase().startsWith("x-debug")) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Security Misconfiguration: Active Debug Header Disclosed")
                        .description("Debug profiling header '" + headerName + "' was detected in response.")
                        .severity(ApiFindingSeverity.MEDIUM)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField(headerName)
                        .evidence(headerName + ": " + headerVal)
                        .cweId(CweMapping.CWE_200)
                        .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                        .remediation("Ensure debug profiling features and headers are disabled in non-development environments.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }
        }

        // 2. Missing Standard Defensive Security Headers
        // Check only for normal responses (e.g. 2xx, 3xx, 4xx) where security headers are expected
        boolean hasHsts = hasHeader(headers, "Strict-Transport-Security");
        boolean hasContentTypeOptions = hasHeader(headers, "X-Content-Type-Options");
        boolean hasCsp = hasHeader(headers, "Content-Security-Policy");

        if (!hasHsts) {
            findings.add(ApiSecurityFinding.builder()
                    .ruleId(RULE_ID)
                    .title("Security Misconfiguration: Missing Strict-Transport-Security (HSTS) Header")
                    .description("The API response is missing the Strict-Transport-Security header, leaving transport encryption vulnerable to downgrade attacks.")
                    .severity(ApiFindingSeverity.LOW)
                    .confidence(ApiFindingConfidence.HIGH)
                    .apiProjectId(projectId)
                    .httpMethod(method)
                    .endpointPath(path)
                    .parameterOrField("Strict-Transport-Security")
                    .evidence("Missing header: Strict-Transport-Security")
                    .cweId(CweMapping.CWE_319)
                    .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                    .remediation("Enable HSTS with 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.")
                    .executionId(executionId)
                    .isConfirmed(true)
                    .build());
        }

        if (!hasContentTypeOptions) {
            findings.add(ApiSecurityFinding.builder()
                    .ruleId(RULE_ID)
                    .title("Security Misconfiguration: Missing X-Content-Type-Options Header")
                    .description("The API response is missing 'X-Content-Type-Options: nosniff', which helps prevent MIME type sniffing.")
                    .severity(ApiFindingSeverity.LOW)
                    .confidence(ApiFindingConfidence.HIGH)
                    .apiProjectId(projectId)
                    .httpMethod(method)
                    .endpointPath(path)
                    .parameterOrField("X-Content-Type-Options")
                    .evidence("Missing header: X-Content-Type-Options")
                    .cweId(CweMapping.CWE_693)
                    .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                    .remediation("Add 'X-Content-Type-Options: nosniff' to all HTTP responses.")
                    .executionId(executionId)
                    .isConfirmed(true)
                    .build());
        }

        if (!hasCsp) {
            findings.add(ApiSecurityFinding.builder()
                    .ruleId(RULE_ID)
                    .title("Security Misconfiguration: Missing Content-Security-Policy Header")
                    .description("The response lacks a Content-Security-Policy header.")
                    .severity(ApiFindingSeverity.INFORMATIONAL)
                    .confidence(ApiFindingConfidence.HIGH)
                    .apiProjectId(projectId)
                    .httpMethod(method)
                    .endpointPath(path)
                    .parameterOrField("Content-Security-Policy")
                    .evidence("Missing header: Content-Security-Policy")
                    .cweId(CweMapping.CWE_693)
                    .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                    .remediation("Define a restrictive Content-Security-Policy appropriate for API payloads.")
                    .executionId(executionId)
                    .isConfirmed(true)
                    .build());
        }

        // 3. Debug Flag in Response Body
        String body = response.responseBody();
        if (body != null && !body.isBlank() && DEBUG_BODY_PATTERN.matcher(body).find()) {
            findings.add(ApiSecurityFinding.builder()
                    .ruleId(RULE_ID)
                    .title("Security Misconfiguration: Application Debug Mode Disclosed in Payload")
                    .description("The response body indicates that application debug mode or development mode is active.")
                    .severity(ApiFindingSeverity.MEDIUM)
                    .confidence(ApiFindingConfidence.HIGH)
                    .apiProjectId(projectId)
                    .httpMethod(method)
                    .endpointPath(path)
                    .parameterOrField("debug")
                    .evidence("Debug flag active in response body")
                    .cweId(CweMapping.CWE_16)
                    .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                    .remediation("Set DEBUG=False and ensure production environment configurations are enforced.")
                    .executionId(executionId)
                    .isConfirmed(true)
                    .build());
        }

        return findings;
    }

    private static boolean hasHeader(Map<String, List<String>> headers, String name) {
        if (headers == null) return false;
        for (String k : headers.keySet()) {
            if (k.equalsIgnoreCase(name)) {
                List<String> vals = headers.get(k);
                return vals != null && !vals.isEmpty() && !vals.get(0).isBlank();
            }
        }
        return false;
    }
}

