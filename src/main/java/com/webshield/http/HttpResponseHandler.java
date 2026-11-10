package com.webshield.http;

import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

/**
 * Transforms Java HttpClient responses into WebShield's {@link HttpResponseData}.
 */
public class HttpResponseHandler {

    private final CookieParser cookieParser;
    private static final int MAX_BODY_CHARACTERS = 2_000_000; // 2MB safety threshold

    public HttpResponseHandler() {
        this(new CookieParser());
    }

    public HttpResponseHandler(CookieParser cookieParser) {
        this.cookieParser = cookieParser;
    }

    public HttpResponseData handleResponse(String requestUrl, HttpResponse<String> rawResponse,
                                           long durationMs, String redirectedTo) {
        if (rawResponse == null) {
            return new HttpResponseData(requestUrl, 0, Map.of(), "", durationMs, List.of(), null);
        }

        int statusCode = rawResponse.statusCode();
        Map<String, List<String>> headers = rawResponse.headers().map();

        String body = rawResponse.body();
        if (body != null && body.length() > MAX_BODY_CHARACTERS) {
            body = body.substring(0, MAX_BODY_CHARACTERS);
        }

        List<String> setCookieHeaders = rawResponse.headers().allValues("set-cookie");
        List<HttpCookieData> cookies = cookieParser.parseCookies(setCookieHeaders);

        return new HttpResponseData(
                requestUrl,
                statusCode,
                headers,
                body != null ? body : "",
                durationMs,
                cookies,
                redirectedTo
        );
    }
}

