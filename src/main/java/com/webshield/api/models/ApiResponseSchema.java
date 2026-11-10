package com.webshield.api.models;

import java.util.*;

/**
 * Representation of an API response definition for a specific HTTP status code.
 */
public class ApiResponseSchema {

    private String statusCode = "default";
    private String description;
    private Map<String, ApiSchema> contentTypes = new LinkedHashMap<>();
    private Map<String, ApiParameter> headers = new LinkedHashMap<>();

    public ApiResponseSchema() {
    }

    public ApiResponseSchema(String statusCode, String description) {
        this.statusCode = statusCode != null ? statusCode : "default";
        this.description = description;
    }

    public ApiSchema getJsonSchema() {
        if (contentTypes.containsKey("application/json")) {
            return contentTypes.get("application/json");
        }
        for (Map.Entry<String, ApiSchema> entry : contentTypes.entrySet()) {
            if (entry.getKey().toLowerCase(Locale.ROOT).contains("json")) {
                return entry.getValue();
            }
        }
        return contentTypes.values().stream().findFirst().orElse(null);
    }

    public boolean isSuccess() {
        return statusCode != null && statusCode.startsWith("2");
    }

    public boolean isClientError() {
        return statusCode != null && statusCode.startsWith("4");
    }

    public boolean isServerError() {
        return statusCode != null && statusCode.startsWith("5");
    }

    public String getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(String statusCode) {
        this.statusCode = statusCode != null ? statusCode : "default";
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Map<String, ApiSchema> getContentTypes() {
        return Collections.unmodifiableMap(contentTypes);
    }

    public void setContentTypes(Map<String, ApiSchema> contentTypes) {
        this.contentTypes = contentTypes != null ? new LinkedHashMap<>(contentTypes) : new LinkedHashMap<>();
    }

    public void addContentType(String mediaType, ApiSchema schema) {
        if (mediaType != null) {
            this.contentTypes.put(mediaType.trim(), schema != null ? schema : new ApiSchema());
        }
    }

    public Map<String, ApiParameter> getHeaders() {
        return Collections.unmodifiableMap(headers);
    }

    public void setHeaders(Map<String, ApiParameter> headers) {
        this.headers = headers != null ? new LinkedHashMap<>(headers) : new LinkedHashMap<>();
    }

    public void addHeader(String headerName, ApiParameter parameter) {
        if (headerName != null) {
            this.headers.put(headerName, parameter);
        }
    }

    @Override
    public String toString() {
        return "ApiResponseSchema{" +
                "statusCode='" + statusCode + '\'' +
                ", contentTypes=" + contentTypes.keySet() +
                '}';
    }
}

