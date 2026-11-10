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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects sensitive information exposure in API response bodies and headers,
 * including passwords, API secret keys, private keys, credit card numbers, and connection strings.
 */
@Component
public class SensitiveDataExposureRule implements ApiSecurityRule {

    public static final String RULE_ID = "RULE-SENSITIVE-DATA";

    private static final Pattern PRIVATE_KEY_PATTERN = Pattern.compile(
            "-----BEGIN (?:RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----");

    private static final Pattern PASSWORD_FIELD_PATTERN = Pattern.compile(
            "(?i)\"(password|passwd|pwd|client_secret|user_password|db_password)\"\\s*:\\s*\"([^\"]+)\"");

    private static final Pattern API_KEY_FIELD_PATTERN = Pattern.compile(
            "(?i)\"(api_key|apikey|secret_key|private_token|access_token)\"\\s*:\\s*\"([^\"]+)\"");

    private static final Pattern AWS_KEY_PATTERN = Pattern.compile(
            "\\b(AKIA[0-9A-Z]{16})\\b");

    private static final Pattern STRIPE_KEY_PATTERN = Pattern.compile(
            "\\b(sk_(?:live|test)_[0-9a-zA-Z]{24,})\\b");

    private static final Pattern GITHUB_TOKEN_PATTERN = Pattern.compile(
            "\\b(ghp_[0-9a-zA-Z]{36})\\b");

    private static final Pattern JWT_PATTERN = Pattern.compile(
            "\\b(eyJ[a-zA-Z0-9_-]{10,}\\.eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,})\\b");

    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile(
            "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b");

    private static final Pattern DB_CONNECTION_PATTERN = Pattern.compile(
            "(?i)\\b(?:jdbc:[a-zA-Z0-9:]+://|mongodb(?:\\+srv)?://|postgres(?:ql)?://)[^\\s\"'<>\\]]+");

    @Override
    public String getRuleId() {
        return RULE_ID;
    }

    @Override
    public String getName() {
        return "Sensitive Data Exposure Detection";
    }

    @Override
    public String getDescription() {
        return "Detects accidental exposure of sensitive credentials, keys, private tokens, or connection strings in HTTP responses.";
    }

    @Override
    public ApiFindingSeverity getSeverity() {
        return ApiFindingSeverity.HIGH;
    }

    @Override
    public OwaspApiCategory getOwaspCategory() {
        return OwaspApiCategory.API3_BOPLA;
    }

    @Override
    public String getCweId() {
        return CweMapping.CWE_200;
    }

    @Override
    public String getRemediation() {
        return "Ensure sensitive data, credentials, cryptographic keys, and internal connection strings are omitted from API responses using DTO projection and field masking.";
    }

    @Override
    public List<ApiSecurityFinding> analyze(ApiExecutionRequest request, ApiExecutionResponse response) {
        List<ApiSecurityFinding> findings = new ArrayList<>();
        if (response == null || !response.connectionSuccessful()) {
            return findings;
        }

        String body = response.responseBody();
        String path = request != null ? request.resolvedPath() : "/";
        Long projectId = request != null ? request.apiProjectId() : null;
        var method = request != null ? request.method() : null;
        String executionId = response.executionId();

        if (body != null && !body.isBlank()) {
            // 1. Private Keys
            if (PRIVATE_KEY_PATTERN.matcher(body).find()) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Sensitive Data Exposure: Cryptographic Private Key Detected")
                        .description("An unencrypted private cryptographic key was returned in the API response body.")
                        .severity(ApiFindingSeverity.CRITICAL)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("private_key")
                        .evidence("[PRIVATE KEY BLOCK REDACTED]")
                        .cweId(CweMapping.CWE_522)
                        .owaspCategory(OwaspApiCategory.API3_BOPLA)
                        .remediation("Immediately revoke the exposed private key and prevent server keys from being returned in API responses.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }

            // 2. Passwords in JSON fields
            Matcher pwMatcher = PASSWORD_FIELD_PATTERN.matcher(body);
            if (pwMatcher.find()) {
                String fieldName = pwMatcher.group(1);
                String rawSnippet = pwMatcher.group(0);
                String safeEvidence = RedactionUtils.redactSensitiveData(rawSnippet);

                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Sensitive Data Exposure: Password Field Exposed in API Response")
                        .description("The API response contains a cleartext or serialized password field ('" + fieldName + "').")
                        .severity(ApiFindingSeverity.HIGH)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField(fieldName)
                        .evidence(safeEvidence)
                        .cweId(CweMapping.CWE_522)
                        .owaspCategory(OwaspApiCategory.API3_BOPLA)
                        .remediation("Exclude passwords and sensitive credentials from API response payloads. Use response DTOs that omit credential fields.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }

            // 3. Cloud & Service API Keys (AWS, Stripe, GitHub)
            if (AWS_KEY_PATTERN.matcher(body).find()) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Sensitive Data Exposure: AWS Access Key ID Detected")
                        .description("An AWS access key identifier was discovered in the response body.")
                        .severity(ApiFindingSeverity.HIGH)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("aws_access_key")
                        .evidence("AKIA****************")
                        .cweId(CweMapping.CWE_200)
                        .owaspCategory(OwaspApiCategory.API3_BOPLA)
                        .remediation("Revoke the exposed AWS credential immediately and store secrets using AWS Secrets Manager or environment variables.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }

            if (STRIPE_KEY_PATTERN.matcher(body).find()) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Sensitive Data Exposure: Stripe API Secret Key Detected")
                        .description("A Stripe live or test secret key was discovered in the response body.")
                        .severity(ApiFindingSeverity.HIGH)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("stripe_key")
                        .evidence("sk_live_****[REDACTED]")
                        .cweId(CweMapping.CWE_200)
                        .owaspCategory(OwaspApiCategory.API3_BOPLA)
                        .remediation("Rotate the compromised Stripe key immediately and never return payment gateway secret keys to client endpoints.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }

            if (GITHUB_TOKEN_PATTERN.matcher(body).find()) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Sensitive Data Exposure: GitHub Personal Access Token Detected")
                        .description("A GitHub personal access token (ghp_) was exposed in the API response.")
                        .severity(ApiFindingSeverity.HIGH)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("github_token")
                        .evidence("ghp_****[REDACTED]")
                        .cweId(CweMapping.CWE_200)
                        .owaspCategory(OwaspApiCategory.API3_BOPLA)
                        .remediation("Revoke the exposed token from GitHub account settings.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }

            // 4. API Key JSON Fields
            Matcher apiKeyMatcher = API_KEY_FIELD_PATTERN.matcher(body);
            if (apiKeyMatcher.find()) {
                String fieldName = apiKeyMatcher.group(1);
                String safeEvidence = RedactionUtils.redactSensitiveData(apiKeyMatcher.group(0));

                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Sensitive Data Exposure: API Secret Key Property Exposed")
                        .description("The API response body contains an API secret key or private access token property ('" + fieldName + "').")
                        .severity(ApiFindingSeverity.HIGH)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField(fieldName)
                        .evidence(safeEvidence)
                        .cweId(CweMapping.CWE_200)
                        .owaspCategory(OwaspApiCategory.API3_BOPLA)
                        .remediation("Ensure API keys and secrets are never returned in public endpoint responses.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }

            // 5. Unexpected JWT exposure on non-auth paths
            boolean isAuthPath = path.toLowerCase().contains("login")
                    || path.toLowerCase().contains("token")
                    || path.toLowerCase().contains("auth")
                    || path.toLowerCase().contains("oauth")
                    || path.toLowerCase().contains("session");

            if (!isAuthPath && JWT_PATTERN.matcher(body).find()) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Sensitive Data Exposure: Unexpected JWT Disclosed in Non-Auth Endpoint")
                        .description("A JSON Web Token (JWT) was disclosed in the response of a non-authentication endpoint.")
                        .severity(ApiFindingSeverity.MEDIUM)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("jwt")
                        .evidence("eyJ****...[JWT REDACTED]")
                        .cweId(CweMapping.CWE_200)
                        .owaspCategory(OwaspApiCategory.API3_BOPLA)
                        .remediation("Restrict JWT issuance and transmission exclusively to designated token or authentication endpoints.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }

            // 6. Credit Card Numbers
            Matcher ccMatcher = CREDIT_CARD_PATTERN.matcher(body);
            if (ccMatcher.find()) {
                String cc = ccMatcher.group();
                String last4 = cc.substring(cc.length() - 4);
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Sensitive Data Exposure: Payment Card Number Disclosed")
                        .description("A payment card Primary Account Number (PAN) was detected in cleartext in the API response.")
                        .severity(ApiFindingSeverity.HIGH)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("pan")
                        .evidence("****-****-****-" + last4)
                        .cweId(CweMapping.CWE_200)
                        .owaspCategory(OwaspApiCategory.API3_BOPLA)
                        .remediation("Comply with PCI-DSS requirements: mask all PAN digits except the last four, or tokenize card data.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }

            // 7. Database Connection Strings
            Matcher dbMatcher = DB_CONNECTION_PATTERN.matcher(body);
            if (dbMatcher.find()) {
                String safeConn = RedactionUtils.redactSensitiveData(dbMatcher.group());
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Sensitive Data Exposure: Internal Database Connection String Exposed")
                        .description("An internal database connection URI was discovered in the response body.")
                        .severity(ApiFindingSeverity.HIGH)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("database_uri")
                        .evidence(safeConn)
                        .cweId(CweMapping.CWE_200)
                        .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                        .remediation("Do not leak backend connection parameters or configuration strings in application responses.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }
        }

        return findings;
    }
}

