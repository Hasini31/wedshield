package com.webshield.api.execution;

import com.webshield.http.HttpClientManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Central API Execution Engine coordinating request safety checks, anti-SSRF validation,
 * rate limiting, concurrency controls, manual redirect tracing, and response capture.
 */
@Service
public class ApiExecutionEngine {

    private static final Logger log = LoggerFactory.getLogger(ApiExecutionEngine.class);
    private static final AtomicInteger EXECUTION_COUNTER = new AtomicInteger(1);

    private final HttpClientManager httpClientManager;
    private final ApiExecutionConfiguration config;
    private final ApiRequestBuilder requestBuilder;
    private final TargetSafetyValidator safetyValidator;
    private final Semaphore concurrencySemaphore;
    private final RateLimiter rateLimiter;

    @org.springframework.beans.factory.annotation.Autowired
    public ApiExecutionEngine(HttpClientManager httpClientManager) {
        this(httpClientManager, ApiExecutionConfiguration.defaultConfig());
    }

    public ApiExecutionEngine(HttpClientManager httpClientManager, ApiExecutionConfiguration config) {
        this.httpClientManager = Objects.requireNonNull(httpClientManager, "httpClientManager must not be null");
        this.config = config != null ? config : ApiExecutionConfiguration.defaultConfig();
        this.requestBuilder = new ApiRequestBuilder();
        this.safetyValidator = new TargetSafetyValidator();
        this.concurrencySemaphore = new Semaphore(this.config.getMaxConcurrentRequests());
        this.rateLimiter = new RateLimiter(this.config.getRequestsPerSecond());
    }

    /**
     * Executes an API test request synchronously with full security, rate limiting, and redirect tracing.
     */
    public ApiExecutionResponse execute(ApiExecutionRequest request) {
        String executionId = "EXEC-" + EXECUTION_COUNTER.getAndIncrement() + "-" + UUID.randomUUID().toString().substring(0, 8);
        if (request == null) {
            return ApiExecutionResponse.failure(executionId, "UNKNOWN", ExecutionOutcome.INVALID_REQUEST, "Request cannot be null");
        }

        // 1. Validate Unsafe Method Authorization Policy
        if (!config.isAllowUnsafeMethods() && !request.isSafeMethod()) {
            log.warn("Blocked mutating HTTP method {} by policy: {}", request.method(), request.fullUrl());
            return ApiExecutionResponse.failure(executionId, request.testCaseId(), ExecutionOutcome.POLICY_BLOCKED,
                    "Mutating HTTP method " + request.method() + " is disabled by execution safety policy");
        }

        // 2. Initial Target Safety & Anti-SSRF Validation
        URI targetUri;
        try {
            targetUri = new URI(request.fullUrl());
            safetyValidator.validateTarget(targetUri, config.isAllowLocalAddresses(), null);
        } catch (URISyntaxException | IllegalArgumentException e) {
            log.warn("Invalid target URL syntax: {}", request.fullUrl());
            return ApiExecutionResponse.failure(executionId, request.testCaseId(), ExecutionOutcome.INVALID_REQUEST,
                    "Invalid URL: " + e.getMessage());
        } catch (SecurityException e) {
            log.warn("Target blocked by security policy: {}", e.getMessage());
            return ApiExecutionResponse.failure(executionId, request.testCaseId(), ExecutionOutcome.POLICY_BLOCKED,
                    e.getMessage());
        }

        // 3. Acquire Concurrency Semaphore & Rate Limiting Permit
        boolean permitAcquired = false;
        try {
            permitAcquired = concurrencySemaphore.tryAcquire(config.getRequestTimeout().toMillis(), TimeUnit.MILLISECONDS);
            if (!permitAcquired) {
                return ApiExecutionResponse.failure(executionId, request.testCaseId(), ExecutionOutcome.TIMEOUT,
                        "Execution timed out waiting for concurrency permit");
            }

            rateLimiter.acquire();

            return executeWithRedirects(executionId, request, targetUri);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ApiExecutionResponse.failure(executionId, request.testCaseId(), ExecutionOutcome.EXECUTION_ERROR,
                    "Execution interrupted: " + e.getMessage());
        } finally {
            if (permitAcquired) {
                concurrencySemaphore.release();
            }
        }
    }

    /**
     * Executes the HTTP request and traces redirects up to configured thresholds.
     */
    private ApiExecutionResponse executeWithRedirects(String executionId, ApiExecutionRequest request, URI initialUri) {
        HttpClient client = httpClientManager.getHttpClient();
        URI currentUri = initialUri;
        List<String> redirectUrls = new ArrayList<>();
        int redirectCount = 0;
        long totalDurationMs = 0;

        HttpRequest nativeRequest;
        try {
            nativeRequest = requestBuilder.buildNativeRequest(request, config);
        } catch (Exception e) {
            return ApiExecutionResponse.failure(executionId, request.testCaseId(), ExecutionOutcome.INVALID_REQUEST,
                    "Failed to build native HTTP request: " + e.getMessage());
        }

        while (true) {
            long start = System.currentTimeMillis();
            HttpResponse<String> rawResponse;

            try {
                rawResponse = client.send(nativeRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                long duration = System.currentTimeMillis() - start;
                totalDurationMs += duration;

            } catch (HttpTimeoutException e) {
                long duration = System.currentTimeMillis() - start;
                log.warn("HTTP request timed out to {}: {}", currentUri, e.getMessage());
                return ApiExecutionResponse.failure(executionId, request.testCaseId(), ExecutionOutcome.TIMEOUT,
                        "Request timed out: " + e.getMessage());
            } catch (IOException e) {
                log.warn("Connection failure to {}: {}", currentUri, e.getMessage());
                return ApiExecutionResponse.failure(executionId, request.testCaseId(), ExecutionOutcome.CONNECTION_ERROR,
                        "Transport error: " + e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return ApiExecutionResponse.failure(executionId, request.testCaseId(), ExecutionOutcome.EXECUTION_ERROR,
                        "Execution interrupted: " + e.getMessage());
            }

            int statusCode = rawResponse.statusCode();

            // Check Redirects
            if (isRedirectStatus(statusCode)) {
                Optional<String> locationOpt = rawResponse.headers().firstValue("Location");
                if (locationOpt.isPresent()) {
                    redirectCount++;
                    if (redirectCount > config.getMaxRedirects()) {
                        log.warn("Exceeded maximum redirect limit ({}) for {}", config.getMaxRedirects(), initialUri);
                        return ApiExecutionResponse.failure(executionId, request.testCaseId(), ExecutionOutcome.REDIRECT_BLOCKED,
                                "Exceeded maximum allowed redirects (" + config.getMaxRedirects() + ")");
                    }

                    String locationStr = locationOpt.get().trim();
                    URI nextUri;
                    try {
                        nextUri = currentUri.resolve(locationStr);
                        // Re-validate redirect destination through Anti-SSRF safety validator
                        safetyValidator.validateTarget(nextUri, config.isAllowLocalAddresses(), null);
                    } catch (Exception e) {
                        log.warn("Blocked unsafe redirect from {} to {}: {}", currentUri, locationStr, e.getMessage());
                        return ApiExecutionResponse.failure(executionId, request.testCaseId(), ExecutionOutcome.REDIRECT_BLOCKED,
                                "Redirect blocked by safety policy: " + e.getMessage());
                    }

                    redirectUrls.add(nextUri.toString());
                    currentUri = nextUri;

                    // Build redirect request (always GET for standard redirects)
                    nativeRequest = HttpRequest.newBuilder()
                            .uri(currentUri)
                            .timeout(config.getRequestTimeout())
                            .header("User-Agent", config.getUserAgent())
                            .GET()
                            .build();

                    continue;
                }
            }

            // Normal response termination
            String responseBody = rawResponse.body() != null ? rawResponse.body() : "";
            long originalSize = responseBody.getBytes(StandardCharsets.UTF_8).length;

            // Bounded response body reading to protect memory
            if (originalSize > config.getMaxResponseSizeBytes()) {
                int limit = (int) Math.min(responseBody.length(), config.getMaxResponseSizeBytes());
                responseBody = responseBody.substring(0, limit) + "\n... [TRUNCATED - EXCEEDED MAXIMUM SIZE LIMIT]";
            }

            String contentType = rawResponse.headers().firstValue("Content-Type").orElse("text/plain");
            ExecutionOutcome outcome = classifyStatusCode(statusCode);

            return new ApiExecutionResponse(
                    executionId,
                    request.testCaseId(),
                    statusCode,
                    rawResponse.headers().map(),
                    responseBody,
                    contentType,
                    originalSize,
                    totalDurationMs,
                    redirectCount,
                    redirectUrls,
                    true,
                    outcome,
                    null,
                    Instant.now()
            );
        }
    }

    /**
     * Executes an API test request asynchronously.
     */
    public CompletableFuture<ApiExecutionResponse> executeAsync(ApiExecutionRequest request) {
        return CompletableFuture.supplyAsync(() -> execute(request));
    }

    /**
     * Executes an entire suite of API test requests.
     */
    public List<ApiExecutionResponse> executeSuite(List<ApiExecutionRequest> requests) {
        if (requests == null || requests.isEmpty()) {
            return List.of();
        }
        List<ApiExecutionResponse> results = new ArrayList<>(requests.size());
        for (ApiExecutionRequest req : requests) {
            results.add(execute(req));
        }
        return Collections.unmodifiableList(results);
    }

    private boolean isRedirectStatus(int statusCode) {
        return statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308;
    }

    private ExecutionOutcome classifyStatusCode(int status) {
        if (status >= 200 && status < 300) return ExecutionOutcome.SUCCESS;
        if (status >= 400 && status < 500) return ExecutionOutcome.CLIENT_ERROR;
        if (status >= 500 && status < 600) return ExecutionOutcome.SERVER_ERROR;
        return ExecutionOutcome.SUCCESS;
    }

    public ApiExecutionConfiguration getConfig() {
        return config;
    }

    public ApiRequestBuilder getRequestBuilder() {
        return requestBuilder;
    }

    public TargetSafetyValidator getSafetyValidator() {
        return safetyValidator;
    }
}
