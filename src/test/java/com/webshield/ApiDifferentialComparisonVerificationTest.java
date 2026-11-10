package com.webshield;

import com.webshield.api.analysis.ApiFindingSeverity;
import com.webshield.api.analysis.ApiSecurityAnalyzer;
import com.webshield.api.analysis.ApiSecurityFinding;
import com.webshield.api.dto.ApiFindingDto;
import com.webshield.api.dto.ApiScanComparisonDto;
import com.webshield.api.dto.ApiScanDto;
import com.webshield.api.execution.ApiExecutionRequest;
import com.webshield.api.execution.ApiExecutionResponse;
import com.webshield.api.execution.ExecutionOutcome;
import com.webshield.api.models.HttpMethod;
import com.webshield.api.service.ApiPersistenceService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Controlled verification suite for API Differential Comparison & Regression Engine.
 */
public class ApiDifferentialComparisonVerificationTest {

    private final ApiSecurityAnalyzer securityAnalyzer = new ApiSecurityAnalyzer();

    @Test
    @DisplayName("Verify Security Analyzer detects fixed headers and new SQL injection")
    void testSecurityAnalyzerDifferentialBehavior() {
        // 1. Baseline Old API Auth Response
        ApiExecutionRequest reqAuth = new ApiExecutionRequest(
                "TC-01", 1L, "http://localhost:8080", HttpMethod.POST,
                "/auth/login", "http://localhost:8080/auth/login", Map.of(), Map.of(), Map.of(),
                "{\"username\":\"admin\",\"password\":\"secret\"}", "application/json", Instant.now(), Map.of()
        );
        ApiExecutionResponse respOldAuth = new ApiExecutionResponse(
                "EXEC-01", "TC-01", 200,
                Map.of("Content-Type", List.of("application/json"), "X-Powered-By", List.of("Express/4.17.1")),
                "{\"status\":\"success\"}", "application/json", 30L, 25L, 0, List.of(), true,
                ExecutionOutcome.SUCCESS, null, Instant.now()
        );
        List<ApiSecurityFinding> baselineFindings = securityAnalyzer.analyze(reqAuth, respOldAuth);
        assertEquals(5, baselineFindings.size(), "Old auth response should have 5 misconfiguration findings");

        // 2. Modified New API Auth Response (X-Powered-By removed, nosniff added, no-store added)
        ApiExecutionResponse respNewAuth = new ApiExecutionResponse(
                "EXEC-02", "TC-01", 200,
                Map.of(
                        "Content-Type", List.of("application/json"),
                        "X-Content-Type-Options", List.of("nosniff"),
                        "Cache-Control", List.of("no-store, no-cache, must-revalidate")
                ),
                "{\"status\":\"success\"}", "application/json", 30L, 25L, 0, List.of(), true,
                ExecutionOutcome.SUCCESS, null, Instant.now()
        );
        List<ApiSecurityFinding> newAuthFindings = securityAnalyzer.analyze(reqAuth, respNewAuth);
        assertEquals(2, newAuthFindings.size(), "New auth response should only have HSTS and CSP findings (3 fixed)");

        // 3. New API Coupon SQL Injection Endpoint
        ApiExecutionRequest reqCoupon = new ApiExecutionRequest(
                "TC-SQLI", 2L, "http://localhost:8080", HttpMethod.POST,
                "/coupons/validate", "http://localhost:8080/coupons/validate", Map.of(), Map.of(), Map.of(),
                "{\"couponCode\":\"' OR 1=1 --\"}", "application/json", Instant.now(), Map.of()
        );
        ApiExecutionResponse respCouponSqli = new ApiExecutionResponse(
                "EXEC-03", "TC-SQLI", 500,
                Map.of("Content-Type", List.of("application/json"), "X-Content-Type-Options", List.of("nosniff")),
                "{\"error\":\"Database error: You have an error in your SQL syntax near '' OR 1=1 --' at line 1\"}", "application/json",
                80L, 35L, 0, List.of(), true, ExecutionOutcome.SUCCESS, null, Instant.now()
        );
        List<ApiSecurityFinding> couponFindings = securityAnalyzer.analyze(reqCoupon, respCouponSqli);
        assertTrue(couponFindings.stream().anyMatch(f -> "RULE-INJECTION-INDICATOR".equals(f.ruleId())),
                "SQL Injection database error must be detected by RULE-INJECTION-INDICATOR");
    }

    @Test
    @DisplayName("Verify Fingerprint Differential Logic correctly isolates Regressions, Resolved, and Persistent")
    void testDifferentialFingerprintLogic() {
        // Baseline Findings (Old API): 3 findings
        ApiFindingDto fOld1 = createFinding(1L, "RULE-SEC-MISCONFIG", "Tech Disclosed via X-Powered-By", "POST", "/auth/login", "X-Powered-By");
        ApiFindingDto fOld2 = createFinding(2L, "RULE-SEC-MISCONFIG", "Missing HSTS Header", "POST", "/auth/login", "Strict-Transport-Security");
        ApiFindingDto fOld3 = createFinding(3L, "RULE-HTTP-PROTOCOL", "Missing Cache-Control: no-store", "POST", "/auth/login", "Cache-Control");

        // Comparison Findings (New API):
        // - fOld1 (X-Powered-By) and fOld3 (Cache-Control) are RESOLVED
        // - fOld2 (HSTS) is PERSISTENT
        // - fNewSqli (SQL Injection on /coupons/validate) is a NEW REGRESSION
        ApiFindingDto fPersist = createFinding(10L, "RULE-SEC-MISCONFIG", "Missing HSTS Header", "POST", "/auth/login", "Strict-Transport-Security");
        ApiFindingDto fNewSqli = createFinding(11L, "RULE-INJECTION-INDICATOR", "SQL Error Message Disclosed", "POST", "/coupons/validate", "couponCode");

        List<ApiFindingDto> listA = List.of(fOld1, fOld2, fOld3);
        List<ApiFindingDto> listB = List.of(fPersist, fNewSqli);

        Set<String> keysA = new HashSet<>(listA.stream().map(this::fingerprint).toList());
        Set<String> keysB = new HashSet<>(listB.stream().map(this::fingerprint).toList());

        List<ApiFindingDto> newFindings = listB.stream().filter(fb -> !keysA.contains(fingerprint(fb))).toList();
        List<ApiFindingDto> resolved = listA.stream().filter(fa -> !keysB.contains(fingerprint(fa))).toList();
        List<ApiFindingDto> persistent = listB.stream().filter(fb -> keysA.contains(fingerprint(fb))).toList();

        assertEquals(1, newFindings.size(), "Should have exactly 1 new regression");
        assertEquals("/coupons/validate", newFindings.get(0).endpointPath());

        assertEquals(2, resolved.size(), "Should have exactly 2 resolved findings (X-Powered-By and Cache-Control)");

        assertEquals(1, persistent.size(), "Should have exactly 1 persistent finding (HSTS)");
        assertEquals("Strict-Transport-Security", persistent.get(0).parameterOrField());
    }

    private String fingerprint(ApiFindingDto f) {
        String rule = f.ruleId() != null ? f.ruleId().trim() : "";
        String method = f.httpMethod() != null ? f.httpMethod().trim().toUpperCase() : "GET";
        String endpoint = f.endpointPath() != null ? f.endpointPath().trim().toLowerCase() : "";
        String param = f.parameterOrField() != null ? f.parameterOrField().trim().toLowerCase() : "";
        return rule + "|" + method + "|" + endpoint + "|" + param;
    }

    private ApiFindingDto createFinding(Long id, String ruleId, String title, String method, String path, String param) {
        return new ApiFindingDto(
                id, "UUID-" + id, 1L, 1L, "EXEC-1", ruleId, title, "Description", "LOW", "HIGH",
                method, path, param, "evidence", "CWE-16", "API8", "Remediation", true, "ACTIVE", LocalDateTime.now()
        );
    }
}

