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

/**
 * Detects input validation failures including unhandled 500 Internal Server Errors
 * triggered by mutated or boundary test inputs, and missing validation on invalid inputs.
 */
@Component
public class InputValidationRule implements ApiSecurityRule {

    public static final String RULE_ID = "RULE-INPUT-VALIDATION";

    @Override
    public String getRuleId() {
        return RULE_ID;
    }

    @Override
    public String getName() {
        return "Input Validation and Exception Handling Detection";
    }

    @Override
    public String getDescription() {
        return "Detects unhandled 5xx server crashes on mutated inputs and missing validation on malformed requests.";
    }

    @Override
    public ApiFindingSeverity getSeverity() {
        return ApiFindingSeverity.MEDIUM;
    }

    @Override
    public OwaspApiCategory getOwaspCategory() {
        return OwaspApiCategory.API8_SECURITY_MISCONFIGURATION;
    }

    @Override
    public String getCweId() {
        return CweMapping.CWE_20;
    }

    @Override
    public String getRemediation() {
        return "Implement comprehensive input validation against OpenAPI schema constraints (types, formats, boundaries) and return clean 400 Bad Request or 422 Unprocessable Entity HTTP responses instead of crashing with 500.";
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
        String testCaseId = request != null ? request.testCaseId() : "";

        boolean isMutatedOrInvalid = false;
        if (request != null && request.metadata() != null) {
            if (Boolean.TRUE.equals(request.metadata().get("isMutated"))
                    || request.metadata().containsKey("mutationType")
                    || "INVALID".equalsIgnoreCase(String.valueOf(request.metadata().get("expectedOutcome")))) {
                isMutatedOrInvalid = true;
            }
        }
        if (testCaseId != null && (testCaseId.startsWith("MUT-") || testCaseId.startsWith("TC-INVALID") || testCaseId.startsWith("TC-BOUNDARY"))) {
            isMutatedOrInvalid = true;
        }

        // 1. Unhandled 500 Internal Server Error
        if (response.is5xxServerError()) {
            if (isMutatedOrInvalid) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Input Validation Failure: Server Crash (500) on Mutated/Boundary Input")
                        .description("Submitting a boundary or mutated test input caused an unhandled HTTP " + response.statusCode() + " server crash instead of a graceful 400 or 422 client validation rejection.")
                        .severity(ApiFindingSeverity.MEDIUM)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("payload")
                        .evidence("HTTP status " + response.statusCode() + " for test case " + testCaseId)
                        .cweId(CweMapping.CWE_20)
                        .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                        .remediation("Validate all parameter types, string lengths, and schema bounds before processing business logic.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            } else {
                // Normal request causing 500: potential unhandled server error, but NOT high/critical without explicit error signature
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Input Validation: Unhandled 500 Server Error Disclosed")
                        .description("Endpoint returned HTTP " + response.statusCode() + " Internal Server Error.")
                        .severity(ApiFindingSeverity.LOW)
                        .confidence(ApiFindingConfidence.MEDIUM)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("status")
                        .evidence("HTTP status " + response.statusCode())
                        .cweId(CweMapping.CWE_754)
                        .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                        .remediation("Ensure endpoints handle unexpected states gracefully with appropriate 4xx or sanitized 5xx responses.")
                        .executionId(executionId)
                        .isConfirmed(false)
                        .build());
            }
        }

        // 2. Missing Input Validation (200 OK on explicitly invalid test case)
        if (response.is2xxSuccess() && isMutatedOrInvalid) {
            boolean isExplicitlyInvalid = testCaseId != null && testCaseId.startsWith("TC-INVALID");
            if (request != null && request.metadata() != null && "INVALID".equalsIgnoreCase(String.valueOf(request.metadata().get("expectedOutcome")))) {
                isExplicitlyInvalid = true;
            }

            if (isExplicitlyInvalid) {
                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Input Validation: Missing Validation on Schema-Violating Request")
                        .description("The endpoint accepted an invalid or schema-violating request with HTTP 200 OK without rejecting it.")
                        .severity(ApiFindingSeverity.LOW)
                        .confidence(ApiFindingConfidence.MEDIUM)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("requestBody")
                        .evidence("HTTP " + response.statusCode() + " OK for invalid input in " + testCaseId)
                        .cweId(CweMapping.CWE_20)
                        .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                        .remediation("Enforce strict request body and parameter validation using schema validators (e.g. Hibernate Validator / Jakarta Bean Validation).")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
            }
        }

        return findings;
    }
}

