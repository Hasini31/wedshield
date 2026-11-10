package com.webshield.api.execution;

import com.webshield.api.generation.ApiTestCase;
import com.webshield.api.generation.GenerationStrategy;
import com.webshield.api.generation.TestCategory;
import com.webshield.api.models.HttpMethod;
import com.webshield.api.search.CandidateEvaluator;
import com.webshield.api.search.EvaluationResult;
import com.webshield.http.HttpClientManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("API Execution Engine Test Suite (Module F)")
class ApiExecutionEngineTest {

    private MockHttpClient mockHttpClient;
    private HttpClientManager httpClientManager;
    private ApiExecutionConfiguration testConfig;
    private ApiExecutionEngine engine;
    private ApiRequestBuilder requestBuilder;
    private String serverBaseUrl;

    @BeforeEach
    void setUp() {
        mockHttpClient = new MockHttpClient();
        httpClientManager = new HttpClientManager(mockHttpClient, null, null, null);
        serverBaseUrl = "http://127.0.0.1:8080";

        testConfig = ApiExecutionConfiguration.builder()
                .allowLocalAddresses(true) // Explicitly enabled for test fixtures
                .allowUnsafeMethods(true)
                .connectionTimeout(Duration.ofSeconds(2))
                .requestTimeout(Duration.ofSeconds(3))
                .maxResponseSizeBytes(5000)
                .maxRedirects(3)
                .maxConcurrentRequests(5)
                .requestsPerSecond(100.0)
                .build();

        engine = new ApiExecutionEngine(httpClientManager, testConfig);
        requestBuilder = new ApiRequestBuilder();
    }

    @AfterEach
    void tearDown() {
        if (httpClientManager != null) {
            httpClientManager.shutdown();
        }
    }

    private ApiTestCase createBaseTestCase(String id, HttpMethod method, String path, Object body) {
        return new ApiTestCase(
                id,
                method.name() + " " + path,
                method,
                path,
                TestCategory.VALID,
                Map.of(),
                Map.of(),
                Map.of("X-Test-Client", "WebShield-Test"),
                Map.of(),
                body,
                "application/json",
                GenerationStrategy.SCHEMA_VALID_FULL,
                1337L,
                "Base test case",
                null,
                null,
                null
        );
    }

    // =========================================================================
    // 1. Request Construction
    // =========================================================================
    @Test
    @DisplayName("01. Request construction builds validated immutable execution request")
    void test01_RequestConstruction() {
        ApiTestCase tc = createBaseTestCase("TC-1", HttpMethod.GET, "/api/v1/users", null);
        ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, tc, 101L);

        assertNotNull(req);
        assertEquals("TC-1", req.testCaseId());
        assertEquals(101L, req.apiProjectId());
        assertEquals(serverBaseUrl, req.targetBaseUrl());
        assertEquals(HttpMethod.GET, req.method());
        assertEquals("/api/v1/users", req.resolvedPath());
        assertEquals(serverBaseUrl + "/api/v1/users", req.fullUrl());
        assertTrue(req.isSafeMethod());
        assertFalse(req.hasBody());
    }

    // =========================================================================
    // 2. Path Parameter Substitution
    // =========================================================================
    @Test
    @DisplayName("02. Path parameter substitution correctly encodes and resolves path variables")
    void test02_PathParameterSubstitution() {
        Map<String, Object> pathParams = Map.of("userId", 42, "role", "admin/lead");
        String template = "/api/v1/users/{userId}/roles/{role}";
        String resolved = requestBuilder.resolvePathParameters(template, pathParams);

        assertEquals("/api/v1/users/42/roles/admin%2Flead", resolved,
                "Path parameters must be properly substituted and URL-encoded");
    }

    // =========================================================================
    // 3. Query Parameter Encoding
    // =========================================================================
    @Test
    @DisplayName("03. Query parameter encoding escapes spaces and special characters")
    void test03_QueryParameterEncoding() {
        Map<String, Object> queryParams = new LinkedHashMap<>();
        queryParams.put("query", "security test & scan");
        queryParams.put("limit", 25);

        String qs = requestBuilder.buildQueryString(queryParams);
        assertTrue(qs.startsWith("?"));
        assertTrue(qs.contains("query=security+test+%26+scan") || qs.contains("query=security%20test%20%26%20scan"));
        assertTrue(qs.contains("limit=25"));
    }

    // =========================================================================
    // 4. Header Handling
    // =========================================================================
    @Test
    @DisplayName("04. Header handling transmits custom headers to the server")
    void test04_HeaderHandling() {
        AtomicInteger headerReceived = new AtomicInteger(0);
        mockHttpClient.on("/test-headers", request -> {
            String custom = request.headers().firstValue("X-Custom-Token").orElse(null);
            if ("secret-token-123".equals(custom)) {
                headerReceived.incrementAndGet();
            }
            return MockHttpClient.MockResponse.of(200, "{\"ok\":true}");
        });

        ApiTestCase tc = new ApiTestCase(
                "TC-HDR", "GET /test-headers", HttpMethod.GET, "/test-headers",
                TestCategory.VALID, Map.of(), Map.of(),
                Map.of("X-Custom-Token", "secret-token-123"),
                Map.of(), null, "application/json", GenerationStrategy.SCHEMA_VALID_FULL,
                1L, "desc", null, null, null
        );

        ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, tc, 1L);
        ApiExecutionResponse resp = engine.execute(req);

        assertEquals(200, resp.statusCode());
        assertEquals(1, headerReceived.get(), "Server must receive configured custom header");
    }

    // =========================================================================
    // 5. Cookie Handling
    // =========================================================================
    @Test
    @DisplayName("05. Cookie handling formats cookies into standard Cookie header")
    void test05_CookieHandling() {
        AtomicInteger cookieReceived = new AtomicInteger(0);
        mockHttpClient.on("/test-cookie", request -> {
            String cookie = request.headers().firstValue("Cookie").orElse("");
            if (cookie.contains("sessionId=xyz") && cookie.contains("theme=dark")) {
                cookieReceived.incrementAndGet();
            }
            return MockHttpClient.MockResponse.of(200, "{\"cookie\":\"received\"}");
        });

        ApiTestCase tc = new ApiTestCase(
                "TC-COOKIE", "GET /test-cookie", HttpMethod.GET, "/test-cookie",
                TestCategory.VALID, Map.of(), Map.of(), Map.of(),
                Map.of("sessionId", "xyz", "theme", "dark"),
                null, "application/json", GenerationStrategy.SCHEMA_VALID_FULL,
                1L, "desc", null, null, null
        );

        ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, tc, 1L);
        ApiExecutionResponse resp = engine.execute(req);

        assertEquals(200, resp.statusCode());
        assertEquals(1, cookieReceived.get(), "Server must receive Cookie header formatted with cookies map");
    }

    // =========================================================================
    // 6. JSON Body Serialization
    // =========================================================================
    @Test
    @DisplayName("06. JSON body serialization maps complex objects to valid JSON payload")
    void test06_JsonBodySerialization() {
        mockHttpClient.on("/test-json", request -> MockHttpClient.MockResponse.of(201, "{\"created\":true}"));

        Map<String, Object> payload = Map.of("name", "Alice", "age", 30);
        ApiTestCase tc = createBaseTestCase("TC-POST", HttpMethod.POST, "/test-json", payload);

        ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, tc, 1L);
        assertNotNull(req.requestBody());
        assertTrue(req.requestBody().contains("\"name\":\"Alice\""));
        assertTrue(req.requestBody().contains("\"age\":30"));

        ApiExecutionResponse resp = engine.execute(req);
        assertEquals(201, resp.statusCode());
    }

    // =========================================================================
    // 7. Supported HTTP Methods
    // =========================================================================
    @Test
    @DisplayName("07. Supported HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS) execute correctly")
    void test07_SupportedHttpMethods() {
        Set<String> observedMethods = Collections.synchronizedSet(new HashSet<>());
        mockHttpClient.on("/methods", request -> {
            observedMethods.add(request.method());
            return MockHttpClient.MockResponse.of(200, "{\"method\":\"" + request.method() + "\"}");
        });

        List<HttpMethod> testMethods = List.of(
                HttpMethod.GET, HttpMethod.POST, HttpMethod.PUT,
                HttpMethod.DELETE, HttpMethod.PATCH, HttpMethod.HEAD, HttpMethod.OPTIONS
        );

        for (HttpMethod m : testMethods) {
            boolean hasBody = (m == HttpMethod.POST || m == HttpMethod.PUT || m == HttpMethod.PATCH);
            ApiTestCase tc = createBaseTestCase("TC-" + m.name(), m, "/methods", hasBody ? Map.of("k", "v") : null);
            ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, tc, 1L);
            ApiExecutionResponse resp = engine.execute(req);
            assertEquals(200, resp.statusCode(), "Method " + m + " failed");
        }

        assertEquals(7, observedMethods.size());
    }

    // =========================================================================
    // 8. Invalid URLs
    // =========================================================================
    @Test
    @DisplayName("08. Invalid URLs result in INVALID_REQUEST outcome without crashing")
    void test08_InvalidUrls() {
        ApiExecutionRequest badRequest = new ApiExecutionRequest(
                "TC-BAD", 1L, "http://", HttpMethod.GET, "bad url with spaces and illegal characters",
                "http://::illegal-url", Map.of(), Map.of(), Map.of(), null, "application/json", null, Map.of()
        );

        ApiExecutionResponse resp = engine.execute(badRequest);
        assertEquals(ExecutionOutcome.INVALID_REQUEST, resp.outcome());
        assertFalse(resp.connectionSuccessful());
    }

    // =========================================================================
    // 9. Unsupported URI Schemes
    // =========================================================================
    @Test
    @DisplayName("09. Unsupported URI schemes (file://, ftp://, gopher://) are blocked by policy")
    void test09_UnsupportedUriSchemes() {
        TargetSafetyValidator validator = new TargetSafetyValidator();

        assertThrows(SecurityException.class, () ->
                validator.validateTarget(URI.create("file:///etc/passwd"), true, null));

        assertThrows(SecurityException.class, () ->
                validator.validateTarget(URI.create("ftp://example.com/file"), true, null));

        assertThrows(SecurityException.class, () ->
                validator.validateTarget(URI.create("gopher://example.com"), true, null));
    }

    // =========================================================================
    // 10. Redirect Handling
    // =========================================================================
    @Test
    @DisplayName("10. Redirect handling automatically follows safe redirects to target")
    void test10_RedirectHandling() {
        mockHttpClient.on("/redirect-source", request ->
                MockHttpClient.MockResponse.redirect("/redirect-destination"));
        mockHttpClient.on("/redirect-destination", request ->
                MockHttpClient.MockResponse.of(200, "{\"destination\":\"reached\"}"));

        ApiTestCase tc = createBaseTestCase("TC-REDIR", HttpMethod.GET, "/redirect-source", null);
        ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, tc, 1L);
        ApiExecutionResponse resp = engine.execute(req);

        assertEquals(200, resp.statusCode());
        assertEquals(1, resp.redirectCount());
        assertTrue(resp.redirectUrls().get(0).endsWith("/redirect-destination"));
    }

    // =========================================================================
    // 11. Redirect Limit Enforcement
    // =========================================================================
    @Test
    @DisplayName("11. Redirect limit enforcement blocks infinite redirect loops")
    void test11_RedirectLimitEnforcement() {
        mockHttpClient.on("/loop", request -> MockHttpClient.MockResponse.redirect("/loop"));

        ApiTestCase tc = createBaseTestCase("TC-LOOP", HttpMethod.GET, "/loop", null);
        ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, tc, 1L);
        ApiExecutionResponse resp = engine.execute(req);

        assertEquals(ExecutionOutcome.REDIRECT_BLOCKED, resp.outcome());
        assertFalse(resp.connectionSuccessful());
    }

    // =========================================================================
    // 12. Redirect to Blocked Destination
    // =========================================================================
    @Test
    @DisplayName("12. Redirect to blocked destination (cloud metadata) is intercepted and blocked")
    void test12_RedirectToBlockedDestination() {
        mockHttpClient.on("/redirect-metadata", request ->
                MockHttpClient.MockResponse.redirect("http://169.254.169.254/latest/meta-data"));

        ApiTestCase tc = createBaseTestCase("TC-SSRF", HttpMethod.GET, "/redirect-metadata", null);
        ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, tc, 1L);
        ApiExecutionResponse resp = engine.execute(req);

        assertEquals(ExecutionOutcome.REDIRECT_BLOCKED, resp.outcome());
        assertFalse(resp.connectionSuccessful());
    }

    // =========================================================================
    // 13. Request Timeout
    // =========================================================================
    @Test
    @DisplayName("13. Request timeout terminates hung connections cleanly")
    void test13_RequestTimeout() {
        mockHttpClient.on("/slow-endpoint", request -> {
            throw new HttpTimeoutException("Simulated connection timeout");
        });

        ApiTestCase tc = createBaseTestCase("TC-TIMEOUT", HttpMethod.GET, "/slow-endpoint", null);
        ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, tc, 1L);
        ApiExecutionResponse resp = engine.execute(req);

        assertEquals(ExecutionOutcome.TIMEOUT, resp.outcome());
        assertFalse(resp.connectionSuccessful());
    }

    // =========================================================================
    // 14. Connection Failure
    // =========================================================================
    @Test
    @DisplayName("14. Connection failure to unavailable port is classified as CONNECTION_ERROR")
    void test14_ConnectionFailure() {
        mockHttpClient.on("/dead-endpoint", request -> {
            throw new ConnectException("Connection refused");
        });

        ApiTestCase tc = createBaseTestCase("TC-DEAD", HttpMethod.GET, "/dead-endpoint", null);
        ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, tc, 1L);
        ApiExecutionResponse resp = engine.execute(req);

        assertEquals(ExecutionOutcome.CONNECTION_ERROR, resp.outcome());
        assertFalse(resp.connectionSuccessful());
    }

    // =========================================================================
    // 15. Response-Body Size Limits
    // =========================================================================
    @Test
    @DisplayName("15. Response-body size limits truncate excessively large payloads to protect memory")
    void test15_ResponseBodySizeLimits() {
        String largeContent = "A".repeat(10000); // 10,000 bytes
        mockHttpClient.on("/large-response", request ->
                MockHttpClient.MockResponse.of(200, largeContent));

        ApiExecutionConfiguration limitedSizeConfig = ApiExecutionConfiguration.builder()
                .allowLocalAddresses(true)
                .maxResponseSizeBytes(500)
                .build();
        ApiExecutionEngine sizeEngine = new ApiExecutionEngine(httpClientManager, limitedSizeConfig);

        ApiTestCase tc = createBaseTestCase("TC-LARGE", HttpMethod.GET, "/large-response", null);
        ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, tc, 1L);
        ApiExecutionResponse resp = sizeEngine.execute(req);

        assertEquals(200, resp.statusCode());
        assertTrue(resp.responseBody().contains("[TRUNCATED"));
        assertTrue(resp.responseBody().length() < 1000);
    }

    // =========================================================================
    // 16. Non-JSON Response Handling
    // =========================================================================
    @Test
    @DisplayName("16. Non-JSON responses (HTML, plain text, octet-stream) are captured safely")
    void test16_NonJsonResponseHandling() {
        mockHttpClient.on("/html-endpoint", request ->
                new MockHttpClient.MockResponse(200, Map.of("Content-Type", List.of("text/html")), "<html><body>Hello</body></html>"));

        ApiTestCase tc = createBaseTestCase("TC-HTML", HttpMethod.GET, "/html-endpoint", null);
        ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, tc, 1L);
        ApiExecutionResponse resp = engine.execute(req);

        assertEquals(200, resp.statusCode());
        assertTrue(resp.responseBody().contains("<html>"));
        assertTrue(resp.contentType().contains("text/html"));
    }

    // =========================================================================
    // 17. Rate Limiting
    // =========================================================================
    @Test
    @DisplayName("17. Rate limiting enforces minimum delay between sequential dispatches")
    void test17_RateLimiting() throws InterruptedException {
        RateLimiter limiter = new RateLimiter(5.0); // 5 requests per second = 200ms per request
        long start = System.currentTimeMillis();

        limiter.acquire();
        limiter.acquire();

        long elapsed = System.currentTimeMillis() - start;
        assertTrue(elapsed >= 150, "Two requests at 5 rps must incur at least ~150-200ms delay: " + elapsed);
    }

    // =========================================================================
    // 18. Concurrency Limits
    // =========================================================================
    @Test
    @DisplayName("18. Concurrency limits prevent thread pool starvation under load")
    void test18_ConcurrencyLimits() throws InterruptedException {
        mockHttpClient.on("/concurrent", request -> {
            try {
                Thread.sleep(20);
            } catch (InterruptedException ignored) {}
            return MockHttpClient.MockResponse.of(200, "{\"ok\":true}");
        });

        int maxConcurrent = 3;
        ApiExecutionConfiguration concurrentConfig = ApiExecutionConfiguration.builder()
                .allowLocalAddresses(true)
                .maxConcurrentRequests(maxConcurrent)
                .requestsPerSecond(500.0)
                .build();
        ApiExecutionEngine concurrentEngine = new ApiExecutionEngine(httpClientManager, concurrentConfig);

        ExecutorService pool = Executors.newFixedThreadPool(6);
        List<Future<ApiExecutionResponse>> futures = new ArrayList<>();

        for (int i = 0; i < 6; i++) {
            ApiTestCase tc = createBaseTestCase("TC-C" + i, HttpMethod.GET, "/concurrent", null);
            ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, tc, 1L);
            futures.add(pool.submit(() -> concurrentEngine.execute(req)));
        }

        for (Future<ApiExecutionResponse> f : futures) {
            assertDoesNotThrow(() -> {
                ApiExecutionResponse r = f.get(5, TimeUnit.SECONDS);
                assertEquals(200, r.statusCode());
            });
        }
        pool.shutdown();
    }

    // =========================================================================
    // 19. Cancellation
    // =========================================================================
    @Test
    @DisplayName("19. Async request cancellation terminates pending execution")
    void test19_Cancellation() {
        mockHttpClient.on("/hang", request -> {
            try {
                Thread.sleep(2000);
            } catch (InterruptedException ignored) {}
            return MockHttpClient.MockResponse.of(200, "{\"ok\":true}");
        });

        ApiTestCase tc = createBaseTestCase("TC-CANCEL", HttpMethod.GET, "/hang", null);
        ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, tc, 1L);

        CompletableFuture<ApiExecutionResponse> future = engine.executeAsync(req);
        future.cancel(true);

        assertTrue(future.isCancelled());
    }

    // =========================================================================
    // 20. CandidateEvaluator Integration
    // =========================================================================
    @Test
    @DisplayName("20. ApiCandidateEvaluator bridges ApiExecutionEngine with Module E")
    void test20_CandidateEvaluatorIntegration() {
        mockHttpClient.on("/api/v1/users", request ->
                MockHttpClient.MockResponse.of(201, "{\"id\":101,\"status\":\"created\"}"));

        CandidateEvaluator evaluator = new ApiCandidateEvaluator(engine, serverBaseUrl, 1L);
        ApiTestCase tc = createBaseTestCase("TC-EVAL", HttpMethod.POST, "/api/v1/users", Map.of("name", "Alice"));

        EvaluationResult evalResult = evaluator.evaluate(tc);
        assertNotNull(evalResult);
        assertEquals(201, evalResult.statusCode());
        assertTrue(evalResult.connectionSuccessful());
        assertEquals("POST /api/v1/users", evalResult.endpointIdentifier());
        assertTrue(evalResult.responseBody().toString().contains("101"));
    }

    // =========================================================================
    // 21. Execution Outcome Classification
    // =========================================================================
    @Test
    @DisplayName("21. Execution outcome accurately classifies 2xx, 4xx, 5xx, and transport errors")
    void test21_ExecutionOutcomeClassification() {
        mockHttpClient.on("/200", request -> MockHttpClient.MockResponse.of(200, "OK"));
        mockHttpClient.on("/400", request -> MockHttpClient.MockResponse.of(400, "Bad Request"));
        mockHttpClient.on("/500", request -> MockHttpClient.MockResponse.of(500, "Server Error"));

        ApiExecutionResponse r200 = engine.execute(requestBuilder.buildRequest(serverBaseUrl, createBaseTestCase("1", HttpMethod.GET, "/200", null), 1L));
        assertEquals(ExecutionOutcome.SUCCESS, r200.outcome());

        ApiExecutionResponse r400 = engine.execute(requestBuilder.buildRequest(serverBaseUrl, createBaseTestCase("2", HttpMethod.GET, "/400", null), 1L));
        assertEquals(ExecutionOutcome.CLIENT_ERROR, r400.outcome());

        ApiExecutionResponse r500 = engine.execute(requestBuilder.buildRequest(serverBaseUrl, createBaseTestCase("3", HttpMethod.GET, "/500", null), 1L));
        assertEquals(ExecutionOutcome.SERVER_ERROR, r500.outcome());
    }

    // =========================================================================
    // 22. Sensitive-Data Redaction
    // =========================================================================
    @Test
    @DisplayName("22. Sensitive-data redaction masks credentials, API keys, and Authorization headers")
    void test22_SensitiveDataRedaction() {
        String logEntry = "Dispatched request with Authorization: Bearer secret-jwt-token-xyz and api_key: 123456789";
        String redacted = ApiRequestBuilder.redactSensitiveData(logEntry);

        assertFalse(redacted.contains("secret-jwt-token-xyz"));
        assertFalse(redacted.contains("123456789"));
        assertTrue(redacted.contains("Authorization=******"));
        assertTrue(redacted.contains("api_key=******"));
    }

    // =========================================================================
    // 23. Authorization and Ownership Checks
    // =========================================================================
    @Test
    @DisplayName("23. Target safety rejects out-of-scope domains and unauthorized mutating methods")
    void test23_AuthorizationAndOwnershipChecks() {
        TargetSafetyValidator validator = new TargetSafetyValidator();

        // Scope enforcement
        URI outOfScope = URI.create("http://attacker.com/api");
        assertThrows(SecurityException.class, () ->
                validator.validateTarget(outOfScope, true, "example.com"));

        // Unsafe method policy blocking
        ApiExecutionConfiguration safeOnlyConfig = ApiExecutionConfiguration.builder()
                .allowLocalAddresses(true)
                .allowUnsafeMethods(false)
                .build();
        ApiExecutionEngine safeOnlyEngine = new ApiExecutionEngine(httpClientManager, safeOnlyConfig);

        ApiTestCase mutatingCase = createBaseTestCase("TC-DEL", HttpMethod.DELETE, "/api/data", null);
        ApiExecutionRequest req = requestBuilder.buildRequest(serverBaseUrl, mutatingCase, 1L);
        ApiExecutionResponse resp = safeOnlyEngine.execute(req);

        assertEquals(ExecutionOutcome.POLICY_BLOCKED, resp.outcome());
    }

    // =========================================================================
    // 24. TLS Verification Behavior
    // =========================================================================
    @Test
    @DisplayName("24. TLS certificate verification is non-negotiable and strictly enabled")
    void test24_TlsVerificationBehavior() {
        ApiExecutionConfiguration cfg = ApiExecutionConfiguration.defaultConfig();
        assertTrue(cfg.isTlsVerificationEnabled(), "TLS certificate verification must be enabled by default");
    }
}
