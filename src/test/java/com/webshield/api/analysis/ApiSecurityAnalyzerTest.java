package com.webshield.api.analysis;

import com.webshield.api.analysis.rules.AuthenticationWeaknessRule;
import com.webshield.api.analysis.rules.AuthorizationWeaknessRule;
import com.webshield.api.analysis.rules.HttpProtocolRule;
import com.webshield.api.analysis.rules.InjectionIndicatorRule;
import com.webshield.api.analysis.rules.InputValidationRule;
import com.webshield.api.analysis.rules.SecurityMisconfigurationRule;
import com.webshield.api.analysis.rules.SensitiveDataExposureRule;
import com.webshield.api.execution.ApiExecutionConfiguration;
import com.webshield.api.execution.ApiExecutionEngine;
import com.webshield.api.execution.ApiExecutionRequest;
import com.webshield.api.execution.ApiExecutionResponse;
import com.webshield.api.execution.ApiRequestBuilder;
import com.webshield.api.execution.ExecutionOutcome;
import com.webshield.api.execution.MockHttpClient;
import com.webshield.api.generation.ApiTestCase;
import com.webshield.api.generation.GenerationStrategy;
import com.webshield.api.generation.TestCategory;
import com.webshield.api.models.HttpMethod;
import com.webshield.http.HttpClientManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("API Security Response Analysis Test Suite (Module G)")
class ApiSecurityAnalyzerTest {

    private ApiSecurityAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new ApiSecurityAnalyzer();
    }

    private ApiExecutionRequest createBaseRequest(String testCaseId, HttpMethod method, String path, Map<String, Object> metadata) {
        return new ApiExecutionRequest(
                testCaseId,
                1L,
                "https://api.example.com",
                method,
                path,
                "https://api.example.com" + path,
                Collections.emptyMap(),
                Collections.emptyMap(),
                Collections.emptyMap(),
                "",
                "application/json",
                Instant.now(),
                metadata != null ? metadata : Collections.emptyMap()
        );
    }

    private ApiExecutionResponse createBaseResponse(int statusCode, Map<String, List<String>> headers, String body) {
        return new ApiExecutionResponse(
                "EXEC-001",
                "TC-001",
                statusCode,
                headers != null ? headers : Collections.emptyMap(),
                body != null ? body : "",
                "application/json",
                body != null ? body.length() : 0,
                50L,
                0,
                Collections.emptyList(),
                true,
                ExecutionOutcome.SUCCESS,
                null,
                Instant.now()
        );
    }

    // =========================================================================
    // 1. Rule Registration and Discovery
    // =========================================================================
    @Test
    @DisplayName("1. Rule registration discovers all 7 standard built-in rules and supports custom rules")
    void test01_RuleRegistrationAndDiscovery() {
        List<ApiSecurityRule> registered = analyzer.getRegisteredRules();
        assertNotNull(registered);
        assertEquals(7, registered.size(), "Standard analyzer should register 7 built-in rules");

        ApiSecurityRule customRule = new ApiSecurityRule() {
            @Override public String getRuleId() { return "CUSTOM-01"; }
            @Override public String getName() { return "Custom Test Rule"; }
            @Override public String getDescription() { return "Tests dynamic registration"; }
            @Override public ApiFindingSeverity getSeverity() { return ApiFindingSeverity.LOW; }
            @Override public OwaspApiCategory getOwaspCategory() { return OwaspApiCategory.API8_SECURITY_MISCONFIGURATION; }
            @Override public String getCweId() { return CweMapping.CWE_16; }
            @Override public String getRemediation() { return "Fix custom issue"; }
            @Override public List<ApiSecurityFinding> analyze(ApiExecutionRequest req, ApiExecutionResponse res) {
                return Collections.emptyList();
            }
        };

        analyzer.registerRule(customRule);
        assertEquals(8, analyzer.getRegisteredRules().size());
        assertTrue(analyzer.getRegisteredRules().stream().anyMatch(r -> "CUSTOM-01".equals(r.getRuleId())));
    }

    // =========================================================================
    // 2. Analyzer Orchestration Across Multiple Rules
    // =========================================================================
    @Test
    @DisplayName("2. Analyzer orchestrates multiple rules on a single exchange and aggregates findings")
    void test02_AnalyzerOrchestrationAcrossMultipleRules() {
        ApiExecutionRequest req = createBaseRequest("TC-MULTI", HttpMethod.GET, "/api/data", null);
        Map<String, List<String>> headers = Map.of(
                "Server", List.of("Apache/2.4.41 (Ubuntu)")
                // Missing Strict-Transport-Security and X-Content-Type-Options
        );
        String body = "{\"status\":\"ok\", \"password\": \"SuperSecret123!\"}";
        ApiExecutionResponse resp = createBaseResponse(200, headers, body);

        List<ApiSecurityFinding> findings = analyzer.analyze(req, resp);
        assertNotNull(findings);
        assertTrue(findings.size() >= 3, "Should detect Server banner, missing security headers, and password exposure");

        assertTrue(findings.stream().anyMatch(f -> f.ruleId().equals(SensitiveDataExposureRule.RULE_ID)));
        assertTrue(findings.stream().anyMatch(f -> f.ruleId().equals(SecurityMisconfigurationRule.RULE_ID)));
    }

    // =========================================================================
    // 3. Sensitive Data Detection (Passwords, AWS Keys, Stripe Keys)
    // =========================================================================
    @Test
    @DisplayName("3. SensitiveDataExposureRule identifies passwords, cloud tokens, and API secret keys")
    void test03_SensitiveDataDetectionPasswordsAndTokens() {
        SensitiveDataExposureRule rule = new SensitiveDataExposureRule();
        ApiExecutionRequest req = createBaseRequest("TC-SENSITIVE", HttpMethod.GET, "/api/profile", null);

        // Body containing password, AWS key, and Stripe secret key
        String dummyStripeKey = "sk" + "_live_51A2B3C4D5E6F7G8H9I0J1K2L3M";
        String body = """
                {
                  "user": "alice",
                  "password": "CleartextPassword99",
                  "aws_key": "AKIAIOSFODNN7EXAMPLE",
                  "stripe_token": "%s"
                }
                """.formatted(dummyStripeKey);
        ApiExecutionResponse resp = createBaseResponse(200, Map.of(), body);

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertEquals(3, findings.size(), "Should flag password, AWS key, and Stripe key");

        assertTrue(findings.stream().anyMatch(f -> f.parameterOrField().equals("password")));
        assertTrue(findings.stream().anyMatch(f -> f.parameterOrField().equals("aws_access_key")));
        assertTrue(findings.stream().anyMatch(f -> f.parameterOrField().equals("stripe_key")));
    }

    // =========================================================================
    // 4. Sensitive Data Evidence Redaction
    // =========================================================================
    @Test
    @DisplayName("4. Sensitive data evidence is masked to prevent credential leakage in test reports")
    void test04_SensitiveDataEvidenceRedaction() {
        SensitiveDataExposureRule rule = new SensitiveDataExposureRule();
        ApiExecutionRequest req = createBaseRequest("TC-REDACT", HttpMethod.GET, "/api/account", null);

        String secretValue = "MyUltraSecretPassword123!";
        String body = "{\"user\": \"bob\", \"password\": \"" + secretValue + "\"}";
        ApiExecutionResponse resp = createBaseResponse(200, Map.of(), body);

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertFalse(findings.isEmpty());

        ApiSecurityFinding pwFinding = findings.get(0);
        assertFalse(pwFinding.evidence().contains(secretValue), "Evidence must never contain raw password!");
        assertTrue(pwFinding.evidence().contains("******"), "Evidence must contain masking asterisks");
    }

    // =========================================================================
    // 5. Server Banner and Technology Disclosure
    // =========================================================================
    @Test
    @DisplayName("5. SecurityMisconfigurationRule detects detailed version disclosures in Server headers")
    void test05_ServerBannerAndVersionDisclosure() {
        SecurityMisconfigurationRule rule = new SecurityMisconfigurationRule();
        ApiExecutionRequest req = createBaseRequest("TC-BANNER", HttpMethod.GET, "/api/ping", null);

        Map<String, List<String>> headers = Map.of(
                "Server", List.of("nginx/1.18.0 (Ubuntu)"),
                "X-Powered-By", List.of("Express"),
                "Strict-Transport-Security", List.of("max-age=31536000"),
                "X-Content-Type-Options", List.of("nosniff"),
                "Content-Security-Policy", List.of("default-src 'none'")
        );
        ApiExecutionResponse resp = createBaseResponse(200, headers, "{\"ok\":true}");

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertFalse(findings.isEmpty());

        assertTrue(findings.stream().anyMatch(f -> f.title().contains("Server Banner")));
        assertTrue(findings.stream().anyMatch(f -> f.title().contains("X-Powered-By")));
    }

    // =========================================================================
    // 6. Missing Security Headers Detection
    // =========================================================================
    @Test
    @DisplayName("6. Missing standard security headers (HSTS, nosniff, CSP) are identified with low/info severity")
    void test06_MissingSecurityHeadersDetection() {
        SecurityMisconfigurationRule rule = new SecurityMisconfigurationRule();
        ApiExecutionRequest req = createBaseRequest("TC-HEADERS", HttpMethod.GET, "/api/ping", null);
        ApiExecutionResponse resp = createBaseResponse(200, Map.of(), "{\"ok\":true}");

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertTrue(findings.stream().anyMatch(f -> f.parameterOrField().equals("Strict-Transport-Security")));
        assertTrue(findings.stream().anyMatch(f -> f.parameterOrField().equals("X-Content-Type-Options")));
        assertTrue(findings.stream().anyMatch(f -> f.parameterOrField().equals("Content-Security-Policy")));

        // Verify severity is not inflated to HIGH
        for (ApiSecurityFinding f : findings) {
            assertTrue(f.severity() == ApiFindingSeverity.LOW || f.severity() == ApiFindingSeverity.INFORMATIONAL);
        }
    }

    // =========================================================================
    // 7. Java and Application Stack Trace Detection
    // =========================================================================
    @Test
    @DisplayName("7. InjectionIndicatorRule detects Java runtime exception stack traces")
    void test07_JavaStackTraceDetection() {
        InjectionIndicatorRule rule = new InjectionIndicatorRule();
        ApiExecutionRequest req = createBaseRequest("TC-STACK", HttpMethod.GET, "/api/error", null);

        String stackTraceBody = """
                java.lang.NullPointerException: Cannot invoke method on null object
                    at com.webshield.api.service.UserService.findUser(UserService.java:142)
                    at com.webshield.api.controller.UserController.getUser(UserController.java:55)
                    at org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1072)
                """;
        ApiExecutionResponse resp = createBaseResponse(500, Map.of(), stackTraceBody);

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertFalse(findings.isEmpty());

        ApiSecurityFinding finding = findings.get(0);
        assertEquals(CweMapping.CWE_209, finding.cweId());
        assertTrue(finding.title().contains("Stack Trace"));
    }

    // =========================================================================
    // 8. SQL Database Error Signature Disclosure
    // =========================================================================
    @Test
    @DisplayName("8. InjectionIndicatorRule detects database SQL syntax errors and exposes CWE-209")
    void test08_SqlErrorSignatureDisclosure() {
        InjectionIndicatorRule rule = new InjectionIndicatorRule();
        ApiExecutionRequest req = createBaseRequest("TC-SQL", HttpMethod.GET, "/api/items?q='", null);

        String sqlErrorBody = """
                {"timestamp":"2026-11-04T12:00:00Z","status":500,"error":"Internal Server Error","message":"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1"}
                """;
        ApiExecutionResponse resp = createBaseResponse(500, Map.of(), sqlErrorBody);

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertFalse(findings.isEmpty());

        ApiSecurityFinding finding = findings.get(0);
        assertEquals(CweMapping.CWE_209, finding.cweId());
        assertEquals(ApiFindingSeverity.HIGH, finding.severity());
        assertTrue(finding.evidence().contains("syntax"));
    }

    // =========================================================================
    // 9. Authentication Weakness: Unauthenticated Protected Endpoint
    // =========================================================================
    @Test
    @DisplayName("9. AuthenticationWeaknessRule flags 200 OK responses on protected endpoints without auth headers")
    void test09_AuthenticationBypassDetection() {
        AuthenticationWeaknessRule rule = new AuthenticationWeaknessRule();
        ApiExecutionRequest req = createBaseRequest("TC-NOAUTH", HttpMethod.GET, "/admin/dashboard", Map.of("unauthenticated", true));
        ApiExecutionResponse resp = createBaseResponse(200, Map.of(), "{\"adminData\": \"confidential\", \"users\": 150}");

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertFalse(findings.isEmpty());

        ApiSecurityFinding finding = findings.get(0);
        assertEquals(OwaspApiCategory.API2_BROKEN_AUTH, finding.owaspCategory());
        assertEquals(CweMapping.CWE_287, finding.cweId());
        assertEquals(ApiFindingSeverity.HIGH, finding.severity());
    }

    // =========================================================================
    // 10. Inconsistent Authentication Failure Status (200 OK with Auth Error)
    // =========================================================================
    @Test
    @DisplayName("10. AuthenticationWeaknessRule flags HTTP 200 OK with auth error body as inconsistent status")
    void test10_InconsistentAuthenticationResponse() {
        AuthenticationWeaknessRule rule = new AuthenticationWeaknessRule();
        ApiExecutionRequest req = createBaseRequest("TC-AUTH-200", HttpMethod.POST, "/api/login", null);
        String body = "{\"status\": 200, \"error\": \"unauthorized\", \"message\": \"Access Denied\"}";
        ApiExecutionResponse resp = createBaseResponse(200, Map.of(), body);

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertFalse(findings.isEmpty());

        ApiSecurityFinding finding = findings.get(0);
        assertTrue(finding.title().contains("Inconsistent 200 OK Status"));
        assertEquals(ApiFindingSeverity.MEDIUM, finding.severity());
    }

    // =========================================================================
    // 11. Excessive Data Exposure / BOPLA (Broken Object Property Level Auth)
    // =========================================================================
    @Test
    @DisplayName("11. AuthorizationWeaknessRule flags internal properties (passwordHash, salt, isAdmin)")
    void test11_ExcessiveDataExposureBopla() {
        AuthorizationWeaknessRule rule = new AuthorizationWeaknessRule();
        ApiExecutionRequest req = createBaseRequest("TC-BOPLA", HttpMethod.GET, "/api/v1/users/42", null);

        String body = """
                {
                  "id": 42,
                  "username": "charlie",
                  "passwordHash": "$2a$12$e8kZ1QZ5f6d7g8h9i0j1k2",
                  "salt": "randomSalt123",
                  "isAdmin": true
                }
                """;
        ApiExecutionResponse resp = createBaseResponse(200, Map.of(), body);

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertEquals(2, findings.size(), "Should flag sensitive passwordHash and privilege isAdmin");

        assertTrue(findings.stream().anyMatch(f -> f.parameterOrField().equals("passwordHash")));
        assertTrue(findings.stream().anyMatch(f -> f.parameterOrField().equals("isAdmin")));
    }

    // =========================================================================
    // 12. Broken Object Level Authorization (BOLA / IDOR)
    // =========================================================================
    @Test
    @DisplayName("12. AuthorizationWeaknessRule flags 200 OK on ID substitution with privilege mismatch")
    void test12_BrokenObjectLevelAuthorizationBola() {
        AuthorizationWeaknessRule rule = new AuthorizationWeaknessRule();
        Map<String, Object> metadata = Map.of(
                "privilegeMismatch", true,
                "mutationType", "BOLA_ID_MUTATION"
        );
        ApiExecutionRequest req = createBaseRequest("TC-BOLA-01", HttpMethod.GET, "/api/v1/orders/999", metadata);
        ApiExecutionResponse resp = createBaseResponse(200, Map.of(), "{\"orderId\": 999, \"customer\": \"victim\", \"total\": 450.00}");

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertFalse(findings.isEmpty());

        ApiSecurityFinding finding = findings.get(0);
        assertEquals(OwaspApiCategory.API1_BOLA, finding.owaspCategory());
        assertEquals(ApiFindingSeverity.HIGH, finding.severity());
    }

    // =========================================================================
    // 13. Unhandled Server Error on Mutated/Boundary Input
    // =========================================================================
    @Test
    @DisplayName("13. InputValidationRule flags unhandled 500 crash on mutated input as input validation failure")
    void test13_UnhandledServerErrorOnMutatedInput() {
        InputValidationRule rule = new InputValidationRule();
        Map<String, Object> metadata = Map.of("isMutated", true, "mutationType", "STRING_OVERFLOW");
        ApiExecutionRequest req = createBaseRequest("MUT-OVERFLOW-01", HttpMethod.POST, "/api/v1/feedback", metadata);
        ApiExecutionResponse resp = createBaseResponse(500, Map.of(), "{\"error\":\"Internal Server Error\"}");

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertFalse(findings.isEmpty());

        ApiSecurityFinding finding = findings.get(0);
        assertEquals(CweMapping.CWE_20, finding.cweId());
        assertEquals(ApiFindingSeverity.MEDIUM, finding.severity());
        assertTrue(finding.title().contains("Server Crash (500)"));
    }

    // =========================================================================
    // 14. Missing Input Validation on Explicitly Invalid Request
    // =========================================================================
    @Test
    @DisplayName("14. InputValidationRule flags 200 OK on invalid test case as missing schema validation")
    void test14_MissingInputValidationOnInvalidTestCase() {
        InputValidationRule rule = new InputValidationRule();
        Map<String, Object> metadata = Map.of("expectedOutcome", "INVALID");
        ApiExecutionRequest req = createBaseRequest("TC-INVALID-EMAIL", HttpMethod.POST, "/api/v1/register", metadata);
        ApiExecutionResponse resp = createBaseResponse(200, Map.of(), "{\"id\": 101, \"status\": \"created\"}");

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertFalse(findings.isEmpty());

        ApiSecurityFinding finding = findings.get(0);
        assertEquals(CweMapping.CWE_20, finding.cweId());
        assertTrue(finding.title().contains("Missing Validation"));
    }

    // =========================================================================
    // 15. Content-Type Mismatch (JSON as HTML)
    // =========================================================================
    @Test
    @DisplayName("15. HttpProtocolRule detects JSON body served with text/html Content-Type")
    void test15_ContentTypeMismatchDetection() {
        HttpProtocolRule rule = new HttpProtocolRule();
        ApiExecutionRequest req = createBaseRequest("TC-MIME", HttpMethod.GET, "/api/v1/data", null);
        ApiExecutionResponse resp = new ApiExecutionResponse(
                "E1", "T1", 200,
                Map.of("Content-Type", List.of("text/html; charset=UTF-8")),
                "{\"user\": \"alice\", \"role\": \"developer\"}",
                "text/html; charset=UTF-8",
                40L, 20L, 0, List.of(), true, ExecutionOutcome.SUCCESS, null, Instant.now()
        );

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertFalse(findings.isEmpty());

        ApiSecurityFinding finding = findings.get(0);
        assertTrue(finding.title().contains("Incompatible Content-Type"));
        assertEquals(CweMapping.CWE_16, finding.cweId());
    }

    // =========================================================================
    // 16. Insecure HTTP Methods Exposed (TRACE / TRACK)
    // =========================================================================
    @Test
    @DisplayName("16. HttpProtocolRule detects dangerous TRACE or TRACK method in Allow header")
    void test16_InsecureHttpMethodsExposed() {
        HttpProtocolRule rule = new HttpProtocolRule();
        ApiExecutionRequest req = createBaseRequest("TC-OPTIONS", HttpMethod.OPTIONS, "/api/v1/resource", null);
        ApiExecutionResponse resp = createBaseResponse(200, Map.of("Allow", List.of("GET, POST, TRACE, OPTIONS")), "");

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertFalse(findings.isEmpty());

        ApiSecurityFinding finding = findings.get(0);
        assertTrue(finding.title().contains("TRACE/TRACK"));
        assertEquals(ApiFindingSeverity.MEDIUM, finding.severity());
    }

    // =========================================================================
    // 17. Sensitive Endpoint Missing Cache-Control
    // =========================================================================
    @Test
    @DisplayName("17. HttpProtocolRule detects missing Cache-Control on sensitive authentication endpoints")
    void test17_SensitiveEndpointMissingCacheControl() {
        HttpProtocolRule rule = new HttpProtocolRule();
        ApiExecutionRequest req = createBaseRequest("TC-CACHE", HttpMethod.POST, "/api/v1/auth/login", null);
        ApiExecutionResponse resp = createBaseResponse(200, Map.of(), "{\"token\": \"issued\"}");

        List<ApiSecurityFinding> findings = rule.analyze(req, resp);
        assertFalse(findings.isEmpty());

        ApiSecurityFinding finding = findings.get(0);
        assertEquals(CweMapping.CWE_524, finding.cweId());
        assertTrue(finding.title().contains("Cache-Control"));
    }

    // =========================================================================
    // 18. Severity Classification and Weights
    // =========================================================================
    @Test
    @DisplayName("18. ApiFindingSeverity calculates correct risk weights and converts cleanly to model Severity")
    void test18_SeverityClassificationAndWeights() {
        assertEquals(10, ApiFindingSeverity.CRITICAL.getWeight());
        assertEquals(7, ApiFindingSeverity.HIGH.getWeight());
        assertEquals(4, ApiFindingSeverity.MEDIUM.getWeight());
        assertEquals(2, ApiFindingSeverity.LOW.getWeight());
        assertEquals(0, ApiFindingSeverity.INFORMATIONAL.getWeight());

        assertEquals(com.webshield.assessment.models.Severity.CRITICAL, ApiFindingSeverity.CRITICAL.toModelSeverity());
        assertEquals(ApiFindingSeverity.HIGH, ApiFindingSeverity.fromModelSeverity(com.webshield.assessment.models.Severity.HIGH));
    }

    // =========================================================================
    // 19. Confidence Level Classification
    // =========================================================================
    @Test
    @DisplayName("19. ApiFindingConfidence properly captures High, Medium and Low confidence values")
    void test19_ConfidenceLevelClassification() {
        assertEquals(3, ApiFindingConfidence.values().length);
        assertNotNull(ApiFindingConfidence.valueOf("HIGH"));
        assertNotNull(ApiFindingConfidence.valueOf("MEDIUM"));
        assertNotNull(ApiFindingConfidence.valueOf("LOW"));
    }

    // =========================================================================
    // 20. CWE and OWASP Category Mappings
    // =========================================================================
    @Test
    @DisplayName("20. CweMapping and OwaspApiCategory provide accurate standards definitions and URLs")
    void test20_CweAndOwaspCategoryMappings() {
        assertNotNull(CweMapping.getDescription(CweMapping.CWE_200));
        assertTrue(CweMapping.getUrl(CweMapping.CWE_200).contains("definitions/200.html"));

        for (OwaspApiCategory cat : OwaspApiCategory.values()) {
            assertNotNull(cat.getCode());
            assertNotNull(cat.getTitle());
            assertTrue(cat.getDisplayName().startsWith("API"));
        }
    }

    // =========================================================================
    // 21. Finding Deduplication
    // =========================================================================
    @Test
    @DisplayName("21. ApiSecurityAnalyzer deduplicates identical findings and keeps higher severity")
    void test21_FindingDeduplication() {
        ApiSecurityFinding f1 = ApiSecurityFinding.builder()
                .ruleId("RULE-TEST")
                .endpointPath("/api/v1/data")
                .httpMethod(HttpMethod.GET)
                .parameterOrField("secret")
                .evidence("duplicate evidence")
                .severity(ApiFindingSeverity.LOW)
                .confidence(ApiFindingConfidence.LOW)
                .build();

        ApiSecurityFinding f2 = ApiSecurityFinding.builder()
                .ruleId("RULE-TEST")
                .endpointPath("/api/v1/data")
                .httpMethod(HttpMethod.GET)
                .parameterOrField("secret")
                .evidence("duplicate evidence")
                .severity(ApiFindingSeverity.HIGH)
                .confidence(ApiFindingConfidence.HIGH)
                .build();

        List<ApiSecurityFinding> deduped = analyzer.deduplicate(List.of(f1, f2));
        assertEquals(1, deduped.size(), "Duplicates with identical key must be merged");
        assertEquals(ApiFindingSeverity.HIGH, deduped.get(0).severity(), "Higher severity must be preserved");
    }

    // =========================================================================
    // 22. False Positive Safeguards
    // =========================================================================
    @Test
    @DisplayName("22. False-positive safeguards prevent inflating normal 500s or 200s to SQL injection or BOLA")
    void test22_FalsePositiveSafeguards() {
        // Normal request returning 500 with no SQL error is NOT SQL injection
        ApiExecutionRequest normalReq = createBaseRequest("TC-NORMAL", HttpMethod.GET, "/api/data", null);
        ApiExecutionResponse resp500 = createBaseResponse(500, Map.of(), "{\"error\":\"Service Unavailable\"}");

        List<ApiSecurityFinding> findings500 = analyzer.analyze(normalReq, resp500);
        assertFalse(findings500.stream().anyMatch(f -> f.cweId().equals(CweMapping.CWE_89)),
                "500 alone must never be flagged as SQL injection");

        // Normal 200 response without privilege mismatch metadata is NOT BOLA
        ApiExecutionResponse resp200 = createBaseResponse(200, Map.of(), "{\"id\": 1, \"name\": \"item\"}");
        List<ApiSecurityFinding> findings200 = analyzer.analyze(normalReq, resp200);
        assertFalse(findings200.stream().anyMatch(f -> f.owaspCategory() == OwaspApiCategory.API1_BOLA),
                "200 OK alone without privilege mismatch context must not be flagged as BOLA");
    }

    // =========================================================================
    // 23. Exception Isolation in Analyzer
    // =========================================================================
    @Test
    @DisplayName("23. Exception isolation ensures a failing rule does not abort remaining security rules")
    void test23_ExceptionIsolationInAnalyzer() {
        ApiSecurityRule throwingRule = new ApiSecurityRule() {
            @Override public String getRuleId() { return "RULE-CRASH"; }
            @Override public String getName() { return "Crashing Rule"; }
            @Override public String getDescription() { return "Always throws"; }
            @Override public ApiFindingSeverity getSeverity() { return ApiFindingSeverity.HIGH; }
            @Override public OwaspApiCategory getOwaspCategory() { return OwaspApiCategory.API8_SECURITY_MISCONFIGURATION; }
            @Override public String getCweId() { return CweMapping.CWE_16; }
            @Override public String getRemediation() { return "Fix crash"; }
            @Override public List<ApiSecurityFinding> analyze(ApiExecutionRequest req, ApiExecutionResponse res) {
                throw new RuntimeException("Simulated unexpected crash inside security rule");
            }
        };

        analyzer.registerRule(throwingRule);

        ApiExecutionRequest req = createBaseRequest("TC-CRASH-TEST", HttpMethod.GET, "/api/data", null);
        ApiExecutionResponse resp = createBaseResponse(200, Map.of("Server", List.of("Apache/2.4.41")), "{\"password\":\"secret\"}");

        // Execution should complete normally and return findings from other rules
        assertDoesNotThrow(() -> {
            List<ApiSecurityFinding> findings = analyzer.analyze(req, resp);
            assertFalse(findings.isEmpty(), "Remaining rules must continue executing despite the crash");
        });
    }

    // =========================================================================
    // 24. Empty and Null Responses Safe Handling
    // =========================================================================
    @Test
    @DisplayName("24. Empty and null request/response objects are handled safely without exceptions")
    void test24_EmptyAndNullResponsesSafe() {
        assertDoesNotThrow(() -> {
            List<ApiSecurityFinding> findings1 = analyzer.analyze(null, null);
            assertTrue(findings1.isEmpty());

            ApiExecutionRequest req = createBaseRequest("TC-EMPTY", HttpMethod.GET, "/api/empty", null);
            ApiExecutionResponse failedResp = ApiExecutionResponse.failure("E-1", "T-1", ExecutionOutcome.CONNECTION_ERROR, "Refused");
            List<ApiSecurityFinding> findings2 = analyzer.analyze(req, failedResp);
            assertTrue(findings2.isEmpty());
        });
    }

    // =========================================================================
    // 25. Module F Integration End-to-End
    // =========================================================================
    @Test
    @DisplayName("25. End-to-end integration: Module F execution engine response flows cleanly into Module G analyzer")
    void test25_ModuleFIntegrationEndToEnd() {
        MockHttpClient mockHttpClient = new MockHttpClient();
        HttpClientManager httpClientManager = new HttpClientManager(mockHttpClient, null, null, null);
        String serverBaseUrl = "http://127.0.0.1:8080";

        ApiExecutionConfiguration config = ApiExecutionConfiguration.builder()
                .allowLocalAddresses(true)
                .build();
        ApiExecutionEngine executionEngine = new ApiExecutionEngine(httpClientManager, config);
        ApiRequestBuilder requestBuilder = new ApiRequestBuilder();

        // Target endpoint disclosing AWS key and detailed server banner
        mockHttpClient.on("/api/v1/config", request -> new MockHttpClient.MockResponse(
                200,
                Map.of("Server", List.of("Apache/2.4.41 (Ubuntu)"), "Content-Type", List.of("application/json")),
                "{\"service\": \"payment\", \"key\": \"AKIAIOSFODNN7EXAMPLE\"}"
        ));

        ApiTestCase testCase = new ApiTestCase(
                "TC-E2E-001",
                "GET /api/v1/config",
                HttpMethod.GET,
                "/api/v1/config",
                TestCategory.VALID,
                Map.of(),
                Map.of(),
                Map.of("X-Test-Client", "WebShield-Test"),
                Map.of(),
                null,
                "application/json",
                GenerationStrategy.SCHEMA_VALID_FULL,
                1L,
                "Base test case",
                null,
                null,
                null
        );

        ApiExecutionRequest execRequest = requestBuilder.buildRequest(serverBaseUrl, testCase, 1L);
        ApiExecutionResponse execResponse = executionEngine.execute(execRequest);

        assertEquals(200, execResponse.statusCode());
        assertTrue(execResponse.connectionSuccessful());

        // Feed directly into Module G Analyzer
        List<ApiSecurityFinding> findings = analyzer.analyze(execRequest, execResponse);
        assertNotNull(findings);
        assertFalse(findings.isEmpty(), "Analyzer should detect security weaknesses in Module F response");

        // Verify detected findings
        assertTrue(findings.stream().anyMatch(f -> f.title().contains("AWS Access Key")), "Should detect AWS key");
        assertTrue(findings.stream().anyMatch(f -> f.title().contains("Server Banner")), "Should detect Server banner");
    }
}
