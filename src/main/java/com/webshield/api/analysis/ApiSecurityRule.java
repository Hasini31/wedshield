package com.webshield.api.analysis;

import com.webshield.api.execution.ApiExecutionRequest;
import com.webshield.api.execution.ApiExecutionResponse;

import java.util.List;

/**
 * Interface contract for an API security analysis rule that evaluates captured HTTP execution observations.
 */
public interface ApiSecurityRule {

    /**
     * Unique identifier for the rule (e.g., "RULE-SENSITIVE-DATA").
     */
    String getRuleId();

    /**
     * Human-readable rule name.
     */
    String getName();

    /**
     * Detailed description of what the rule inspects and detects.
     */
    String getDescription();

    /**
     * Default or baseline severity rating for findings produced by this rule.
     */
    ApiFindingSeverity getSeverity();

    /**
     * Primary OWASP API Security Top 10 category mapping.
     */
    OwaspApiCategory getOwaspCategory();

    /**
     * Primary CWE identifier mapping (e.g., "CWE-200").
     */
    String getCweId();

    /**
     * Actionable remediation guidance for developers and security engineers.
     */
    String getRemediation();

    /**
     * Evaluates an HTTP request/response exchange and returns zero or more security findings.
     * Must execute deterministically and safely without side-effects or network calls.
     *
     * @param request the captured outbound HTTP request
     * @param response the captured inbound HTTP response
     * @return non-null list of discovered findings
     */
    List<ApiSecurityFinding> analyze(ApiExecutionRequest request, ApiExecutionResponse response);
}

