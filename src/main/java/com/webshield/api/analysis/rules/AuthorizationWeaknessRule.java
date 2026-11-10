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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects authorization flaws including Broken Object Level Authorization (BOLA / IDOR)
 * and Broken Object Property Level Authorization (excessive data exposure of administrative/internal properties).
 */
@Component
public class AuthorizationWeaknessRule implements ApiSecurityRule {

    public static final String RULE_ID = "RULE-AUTHZ-WEAKNESS";

    private static final Pattern SENSITIVE_PROPERTIES_PATTERN = Pattern.compile(
            "(?i)\"(passwordHash|password_hash|salt|secret_key)\"\\s*:\\s*\"([^\"]+)\"");

    private static final Pattern PRIVILEGE_PROPERTIES_PATTERN = Pattern.compile(
            "(?i)\"(isAdmin|is_admin|role|roles|permissions|internalId|internal_id)\"\\s*:\\s*([^,\"}]+)");

    @Override
    public String getRuleId() {
        return RULE_ID;
    }

    @Override
    public String getName() {
        return "Authorization Weakness Detection";
    }

    @Override
    public String getDescription() {
        return "Detects Broken Object Level Authorization (BOLA) and Object Property Level Authorization (mass assignment / excessive exposure).";
    }

    @Override
    public ApiFindingSeverity getSeverity() {
        return ApiFindingSeverity.HIGH;
    }

    @Override
    public OwaspApiCategory getOwaspCategory() {
        return OwaspApiCategory.API1_BOLA;
    }

    @Override
    public String getCweId() {
        return CweMapping.CWE_284;
    }

    @Override
    public String getRemediation() {
        return "Enforce object-level access controls verifying that the requester owns the target resource, and filter internal or administrative properties from response models.";
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

        // 1. Broken Object Property Level Authorization (BOPLA) - Sensitive & Internal Properties Exposed
        if (body != null && !body.isBlank()) {
            // Highly sensitive properties (passwordHash, salt, secret_key)
            Matcher sensitiveMatcher = SENSITIVE_PROPERTIES_PATTERN.matcher(body);
            if (sensitiveMatcher.find()) {
                String fieldName = sensitiveMatcher.group(1);
                String safeEvidence = RedactionUtils.redactSensitiveData(sensitiveMatcher.group(0));

                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Authorization Weakness: Internal Credential Property Exposed in Response")
                        .description("Response body leaks an internal credential property ('" + fieldName + "').")
                        .severity(ApiFindingSeverity.HIGH)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField(fieldName)
                        .evidence(safeEvidence)
                        .cweId(CweMapping.CWE_200)
                        .owaspCategory(OwaspApiCategory.API3_BOPLA)
                        .remediation("Omit sensitive internal properties like password hashes and salts from response DTOs using Jackson @JsonIgnore.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }

            // Privilege/Internal properties (isAdmin, roles, internalId)
            Matcher privMatcher = PRIVILEGE_PROPERTIES_PATTERN.matcher(body);
            if (privMatcher.find()) {
                String fieldName = privMatcher.group(1);
                String matchSnippet = privMatcher.group(0);

                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Authorization Weakness: Excessive Data Exposure of Internal/Privilege Property")
                        .description("Response payload discloses internal authorization property '" + fieldName + "'.")
                        .severity(ApiFindingSeverity.MEDIUM)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField(fieldName)
                        .evidence(matchSnippet)
                        .cweId(CweMapping.CWE_284)
                        .owaspCategory(OwaspApiCategory.API3_BOPLA)
                        .remediation("Restrict returned properties to only the data strictly required by client applications.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }
        }

        // 2. Broken Object Level Authorization (BOLA / IDOR)
        // Per anti-false-positive rule: Only flag BOLA if request context indicates privilege mismatch or ID substitution
        if (response.is2xxSuccess() && request != null && body != null && body.trim().length() > 2) {
            boolean isBolaTest = false;
            boolean explicitMismatch = false;

            if (request.metadata() != null) {
                if (Boolean.TRUE.equals(request.metadata().get("privilegeMismatch"))) {
                    isBolaTest = true;
                    explicitMismatch = true;
                } else if (Boolean.TRUE.equals(request.metadata().get("bolaCandidate"))) {
                    isBolaTest = true;
                } else {
                    Object mutationType = request.metadata().get("mutationType");
                    if (mutationType != null && mutationType.toString().toUpperCase().contains("BOLA")) {
                        isBolaTest = true;
                    }
                }
            }

            if (request.testCaseId() != null && request.testCaseId().toUpperCase().contains("BOLA")) {
                isBolaTest = true;
            }

            if (isBolaTest) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Broken Object Level Authorization (BOLA): Unauthorized Resource Access")
                        .description("The endpoint returned HTTP 200 OK with full resource payload when accessing an object with a substituted or unauthorized identifier.")
                        .severity(ApiFindingSeverity.HIGH)
                        .confidence(explicitMismatch ? ApiFindingConfidence.HIGH : ApiFindingConfidence.MEDIUM)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("id")
                        .evidence("HTTP " + response.statusCode() + " OK for substituted object identifier on " + path)
                        .cweId(CweMapping.CWE_284)
                        .owaspCategory(OwaspApiCategory.API1_BOLA)
                        .remediation("Validate user authorization at the data-access layer by checking current session ownership against the requested resource ID.")
                        .executionId(executionId)
                        .isConfirmed(explicitMismatch)
                        .build());
            }
        }

        return findings;
    }
}

