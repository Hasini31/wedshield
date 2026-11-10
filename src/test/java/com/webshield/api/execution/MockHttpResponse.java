package com.webshield.api.execution;

import javax.net.ssl.SSLSession;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;

/**
 * In-process mock HttpResponse implementation for testing.
 */
public class MockHttpResponse<T> implements HttpResponse<T> {

    private final int statusCode;
    private final HttpRequest request;
    private final HttpHeaders headers;
    private final T body;
    private final URI uri;

    public MockHttpResponse(int statusCode, HttpRequest request, HttpHeaders headers, T body, URI uri) {
        this.statusCode = statusCode;
        this.request = request;
        this.headers = headers != null ? headers : HttpHeaders.of(java.util.Map.of(), (k, v) -> true);
        this.body = body;
        this.uri = uri;
    }

    @Override
    public int statusCode() {
        return statusCode;
    }

    @Override
    public HttpRequest request() {
        return request;
    }

    @Override
    public Optional<HttpResponse<T>> previousResponse() {
        return Optional.empty();
    }

    @Override
    public HttpHeaders headers() {
        return headers;
    }

    @Override
    public T body() {
        return body;
    }

    @Override
    public Optional<SSLSession> sslSession() {
        return Optional.empty();
    }

    @Override
    public URI uri() {
        return uri;
    }

    @Override
    public HttpClient.Version version() {
        return HttpClient.Version.HTTP_2;
    }
}

