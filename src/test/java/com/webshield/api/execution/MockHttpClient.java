package com.webshield.api.execution;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;

/**
 * In-process mock implementation of Java 21 HttpClient for safe, deterministic, socketless testing.
 */
public class MockHttpClient extends HttpClient {

    @FunctionalInterface
    public interface MockHandler {
        MockResponse handle(HttpRequest request) throws IOException, InterruptedException;
    }

    public record MockResponse(int statusCode, Map<String, List<String>> headers, String body) {
        public static MockResponse of(int code, String body) {
            return new MockResponse(code, Map.of("content-type", List.of("application/json")), body);
        }

        public static MockResponse redirect(String location) {
            return new MockResponse(302, Map.of("Location", List.of(location)), "");
        }
    }

    private final Map<String, MockHandler> routeHandlers = new ConcurrentHashMap<>();
    private MockHandler defaultHandler = req -> MockResponse.of(200, "{\"status\":\"ok\"}");

    public void on(String path, MockHandler handler) {
        routeHandlers.put(path, handler);
    }

    public void setDefaultHandler(MockHandler handler) {
        this.defaultHandler = handler;
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseHandler)
            throws IOException, InterruptedException {
        String path = request.uri().getPath();
        MockHandler handler = routeHandlers.getOrDefault(path, defaultHandler);
        MockResponse resp = handler.handle(request);

        HttpHeaders headers = HttpHeaders.of(resp.headers(), (k, v) -> true);
        T body = (T) resp.body();

        return new MockHttpResponse<>(resp.statusCode(), request, headers, body, request.uri());
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> responseHandler) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return send(request, responseHandler);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> responseHandler, HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        return sendAsync(request, responseHandler);
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return Optional.empty();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return Optional.of(Duration.ofSeconds(2));
    }

    @Override
    public Redirect followRedirects() {
        return Redirect.NEVER;
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return Optional.empty();
    }

    @Override
    public SSLContext sslContext() {
        try {
            return SSLContext.getDefault();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public SSLParameters sslParameters() {
        return new SSLParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return Optional.empty();
    }

    @Override
    public Version version() {
        return Version.HTTP_2;
    }

    @Override
    public Optional<Executor> executor() {
        return Optional.empty();
    }
}

