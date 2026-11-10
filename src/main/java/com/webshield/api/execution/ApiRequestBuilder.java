package com.webshield.api.execution;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webshield.api.generation.ApiTestCase;
import com.webshield.api.models.HttpMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Builds and validates immutable ApiExecutionRequest instances and native Java HttpRequests.
 * Handles path parameter substitution, query string encoding, headers, cookies, and JSON serialization.
 */
public class ApiRequestBuilder {

    private static final Logger log = LoggerFactory.getLogger(ApiRequestBuilder.class);
    private static final Pattern PATH_PARAM_PATTERN = Pattern.compile("\\{([^{}]+)\\}");
    private static final Set<String> RESTRICTED_HEADERS = Set.of(
            "content-length", "host", "connection", "upgrade"
    );

    private final ObjectMapper objectMapper;

    public ApiRequestBuilder() {
        this(new ObjectMapper());
    }

    public ApiRequestBuilder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
    }

    /**
     * Constructs a validated ApiExecutionRequest from an ApiTestCase and target base URL.
     */
    public ApiExecutionRequest buildRequest(String targetBaseUrl, ApiTestCase testCase, Long apiProjectId) {
        if (targetBaseUrl == null || targetBaseUrl.isBlank()) {
            throw new IllegalArgumentException("targetBaseUrl cannot be null or blank");
        }
        if (testCase == null) {
            throw new IllegalArgumentException("testCase cannot be null");
        }

        String rawPath = testCase.path() != null ? testCase.path() : "/";
        String resolvedPath = resolvePathParameters(rawPath, testCase.pathParameters());
        String queryString = buildQueryString(testCase.queryParameters());

        String cleanBase = targetBaseUrl.replaceAll("/+$", "");
        String cleanPath = resolvedPath.startsWith("/") ? resolvedPath : "/" + resolvedPath;
        String fullUrl = cleanBase + cleanPath + queryString;

        // Serialize body if present
        String bodyString = null;
        if (testCase.hasRequestBody()) {
            bodyString = serializeBody(testCase.requestBody());
        }

        // Headers and Cookies
        Map<String, String> headers = new LinkedHashMap<>(testCase.headers());
        if (!testCase.cookies().isEmpty() && !headers.containsKey("Cookie")) {
            headers.put("Cookie", formatCookieHeader(testCase.cookies()));
        }

        String contentType = testCase.contentType() != null ? testCase.contentType() : "application/json";
        if (bodyString != null && !headers.containsKey("Content-Type")) {
            headers.put("Content-Type", contentType);
        }

        return new ApiExecutionRequest(
                testCase.id(),
                apiProjectId,
                cleanBase,
                testCase.method() != null ? testCase.method() : HttpMethod.GET,
                cleanPath,
                fullUrl,
                testCase.queryParameters(),
                headers,
                testCase.cookies(),
                bodyString,
                contentType,
                Instant.now(),
                Map.of("strategy", testCase.strategy() != null ? testCase.strategy().name() : "NONE")
        );
    }

    /**
     * Converts an ApiExecutionRequest to a native Java 21 HttpRequest.
     */
    public HttpRequest buildNativeRequest(ApiExecutionRequest req, ApiExecutionConfiguration config) {
        if (req == null) {
            throw new IllegalArgumentException("ApiExecutionRequest cannot be null");
        }
        ApiExecutionConfiguration activeConfig = config != null ? config : ApiExecutionConfiguration.defaultConfig();

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(req.fullUrl()))
                .timeout(activeConfig.getRequestTimeout());

        // Apply headers
        for (Map.Entry<String, String> entry : req.headers().entrySet()) {
            String name = entry.getKey();
            if (name != null && !isRestrictedHeader(name)) {
                builder.header(name, entry.getValue() != null ? entry.getValue() : "");
            }
        }

        // Apply User-Agent
        builder.header("User-Agent", activeConfig.getUserAgent());

        // Apply HTTP Method and Body
        HttpMethod method = req.method();
        HttpRequest.BodyPublisher publisher = req.hasBody()
                ? HttpRequest.BodyPublishers.ofString(req.requestBody(), StandardCharsets.UTF_8)
                : HttpRequest.BodyPublishers.noBody();

        switch (method) {
            case GET -> builder.GET();
            case POST -> builder.POST(publisher);
            case PUT -> builder.PUT(publisher);
            case DELETE -> builder.DELETE();
            case PATCH -> builder.method("PATCH", publisher);
            case HEAD -> builder.method("HEAD", HttpRequest.BodyPublishers.noBody());
            case OPTIONS -> builder.method("OPTIONS", HttpRequest.BodyPublishers.noBody());
            default -> throw new UnsupportedOperationException("Unsupported HTTP method: " + method);
        }

        return builder.build();
    }

    /**
     * Substitutes {paramName} in path with encoded values.
     */
    public String resolvePathParameters(String template, Map<String, Object> pathParams) {
        if (template == null) return "/";
        if (pathParams == null || pathParams.isEmpty()) return template;

        Matcher matcher = PATH_PARAM_PATTERN.matcher(template);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String paramName = matcher.group(1);
            Object val = pathParams.get(paramName);
            String replacement;
            if (val != null) {
                replacement = URLEncoder.encode(String.valueOf(val), StandardCharsets.UTF_8).replace("+", "%20");
            } else {
                replacement = matcher.group(0); // keep untouched if missing
            }
            matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * Builds and URL-encodes the query parameter string (?key=val&key2=val2).
     */
    public String buildQueryString(Map<String, Object> queryParams) {
        if (queryParams == null || queryParams.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder("?");
        boolean first = true;
        for (Map.Entry<String, Object> entry : queryParams.entrySet()) {
            if (entry.getValue() != null) {
                if (!first) {
                    sb.append("&");
                }
                sb.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
                sb.append("=");
                sb.append(URLEncoder.encode(String.valueOf(entry.getValue()), StandardCharsets.UTF_8));
                first = false;
            }
        }
        return sb.length() > 1 ? sb.toString() : "";
    }

    /**
     * Formats cookie map to a standard HTTP Cookie header string.
     */
    public String formatCookieHeader(Map<String, String> cookies) {
        if (cookies == null || cookies.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> entry : cookies.entrySet()) {
            if (!first) {
                sb.append("; ");
            }
            sb.append(entry.getKey()).append("=").append(entry.getValue() != null ? entry.getValue() : "");
            first = false;
        }
        return sb.toString();
    }

    /**
     * Serializes request body to JSON string if it is an Object or Map.
     */
    public String serializeBody(Object body) {
        if (body == null) return null;
        if (body instanceof String s) return s;
        try {
            return objectMapper.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            log.warn("Failed to serialize body object to JSON: {}", e.getMessage());
            return String.valueOf(body);
        }
    }

    /**
     * Redacts sensitive header values and secret tokens from strings for safe logging.
     */
    public static String redactSensitiveData(String input) {
        if (input == null) return null;
        // Redact Authorization: Bearer <token> or Basic <token>
        String s = input.replaceAll("(?i)authorization[:=]\\s*(?:bearer|basic)?\\s*[^\\s;,]+", "Authorization=******");
        // Redact api-key, secret, password, token, etc.
        return s.replaceAll("(?i)(api[-_]?key|secret|password|cookie|access[-_]?token)[:=]\\s*[^\\s;,]+", "$1=******");
    }

    private boolean isRestrictedHeader(String headerName) {
        return RESTRICTED_HEADERS.contains(headerName.toLowerCase(Locale.ROOT));
    }
}
