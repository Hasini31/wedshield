package com.webshield.http;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe HTTP communication manager using modern Java HttpClient.
 * Shared by both the Crawler and Security Assessment modules.
 */
@Component
public class HttpClientManager {

    private static final Logger log = LoggerFactory.getLogger(HttpClientManager.class);
    private static final AtomicInteger THREAD_COUNTER = new AtomicInteger(1);

    private volatile HttpClient httpClient;
    private final HttpResponseHandler responseHandler;
    private final RedirectHandler redirectHandler;
    private final ExecutorService executor;

    public HttpClientManager() {
        this((HttpClient) null, null, null, null);
    }

    public HttpClientManager(ExecutorService executor) {
        this(null, null, null, executor);
    }

    public HttpClientManager(HttpClient httpClient, HttpResponseHandler responseHandler,
                               RedirectHandler redirectHandler, ExecutorService executor) {
        this.httpClient = httpClient;
        this.responseHandler = responseHandler != null ? responseHandler : new HttpResponseHandler();
        this.redirectHandler = redirectHandler != null ? redirectHandler : new RedirectHandler();
        this.executor = executor != null ? executor : createDefaultExecutor();
    }

    private static ExecutorService createDefaultExecutor() {
        return Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "webshield-http-worker-" + THREAD_COUNTER.getAndIncrement());
            t.setDaemon(true);
            return t;
        });
    }

    @PreDestroy
    public void shutdown() {
        log.debug("Shutting down HttpClientManager executor service...");
        if (executor != null && !executor.isShutdown()) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    public HttpClient getHttpClient() {
        if (this.httpClient == null) {
            synchronized (this) {
                if (this.httpClient == null) {
                    this.httpClient = HttpClient.newBuilder()
                            .version(HttpClient.Version.HTTP_2)
                            .followRedirects(HttpClient.Redirect.NEVER) // Manual safe redirect handling
                            .connectTimeout(Duration.ofSeconds(10))
                            .executor(this.executor)
                            .build();
                }
            }
        }
        return this.httpClient;
    }

    /**
     * Executes an HTTP request synchronously.
     */
    public HttpResponseData execute(HttpRequestData request) throws IOException, InterruptedException {
        return execute(request, null, 0);
    }

    /**
     * Executes an HTTP request synchronously with optional scope validation and max 5 redirects.
     */
    public HttpResponseData execute(HttpRequestData request, String targetDomain) throws IOException, InterruptedException {
        return execute(request, targetDomain, 0);
    }

    private HttpResponseData execute(HttpRequestData request, String targetDomain, int redirectCount)
            throws IOException, InterruptedException {
        validateDestination(request.getUrl());

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(request.getUrl()))
                .timeout(Duration.ofSeconds(request.getTimeoutSeconds()));

        // Apply headers
        for (Map.Entry<String, List<String>> entry : request.getHeaders().entrySet()) {
            String name = entry.getKey();
            for (String val : entry.getValue()) {
                builder.header(name, val);
            }
        }

        // Apply method & body
        if ("POST".equalsIgnoreCase(request.getMethod())) {
            String body = request.getBody() != null ? request.getBody() : "";
            builder.POST(HttpRequest.BodyPublishers.ofString(body));
        } else {
            builder.GET();
        }

        HttpRequest nativeRequest = builder.build();
        long start = System.currentTimeMillis();

        try {
            HttpResponse<String> raw = getHttpClient().send(nativeRequest, HttpResponse.BodyHandlers.ofString());
            long duration = System.currentTimeMillis() - start;

            HttpResponseData response = responseHandler.handleResponse(request.getUrl(), raw, duration, null);

            // Handle safe redirect if present and below threshold
            if (response.isRedirect() && redirectCount < 5) {
                var redirectOpt = redirectHandler.resolveRedirect(request.getUrl(), response, targetDomain);
                if (redirectOpt.isPresent()) {
                    String nextUrl = redirectOpt.get();
                    log.debug("Following safe redirect: {} -> {}", request.getUrl(), nextUrl);
                    HttpRequestData redirectReq = HttpRequestBuilder.get(nextUrl)
                            .timeout(request.getTimeoutSeconds())
                            .build();
                    return execute(redirectReq, targetDomain, redirectCount + 1);
                }
            }

            return response;
        } catch (IOException e) {
            long duration = System.currentTimeMillis() - start;
            log.warn("HTTP request failed to {}: {}", request.getUrl(), e.getMessage());
            throw e;
        }
    }

    /**
     * Executes an HTTP request asynchronously using CompletableFuture.
     */
    public CompletableFuture<HttpResponseData> executeAsync(HttpRequestData request, String targetDomain) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return execute(request, targetDomain);
            } catch (Exception e) {
                log.error("Async HTTP request failed to {}: {}", request.getUrl(), e.getMessage());
                throw new CompletionException(e);
            }
        }, executor);
    }

    /**
     * Defensive safety check preventing access to metadata or non-HTTP schemes.
     */
    private void validateDestination(String url) {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("Destination URL cannot be null or empty.");
        }
        String lower = url.toLowerCase();
        if (!lower.startsWith("http://") && !lower.startsWith("https://")) {
            throw new IllegalArgumentException("Only HTTP/HTTPS URLs are allowed: " + url);
        }
        // Protect cloud metadata endpoints (e.g., AWS/GCP 169.254.169.254)
        if (lower.contains("169.254.169.254") || lower.contains("metadata.google.internal")) {
            throw new SecurityException("Access to cloud metadata endpoints is strictly prohibited: " + url);
        }
    }
}

