package com.webshield.http;

import java.util.Optional;

/**
 * Utility for analyzing HTTP security headers and content characteristics.
 */
public class HttpHeaderAnalyzer {

    public static final String HEADER_CSP = "Content-Security-Policy";
    public static final String HEADER_HSTS = "Strict-Transport-Security";
    public static final String HEADER_X_FRAME_OPTIONS = "X-Frame-Options";
    public static final String HEADER_X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options";
    public static final String HEADER_REFERRER_POLICY = "Referrer-Policy";
    public static final String HEADER_SET_COOKIE = "Set-Cookie";

    public boolean hasHeader(HttpResponseData response, String headerName) {
        return response != null && response.getFirstHeader(headerName).isPresent();
    }

    public Optional<String> getHeaderValue(HttpResponseData response, String headerName) {
        if (response == null) return Optional.empty();
        return response.getFirstHeader(headerName);
    }

    public boolean isHtmlResponse(HttpResponseData response) {
        if (response == null) return false;
        String contentType = response.getContentType().toLowerCase();
        return contentType.contains("text/html") || contentType.contains("application/xhtml");
    }

    public boolean isHttps(String url) {
        return url != null && url.toLowerCase().startsWith("https://");
    }
}

