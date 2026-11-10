package com.webshield.api.models;

import java.util.*;

/**
 * Representation of an HTTP request body with multi-media-type schema mappings.
 */
public class ApiRequestBody {

    private String description;
    private boolean required = false;
    private Map<String, ApiSchema> contentTypes = new LinkedHashMap<>();

    public ApiRequestBody() {
    }

    public ApiRequestBody(String description, boolean required) {
        this.description = description;
        this.required = required;
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

    public ApiSchema getSchema(String contentType) {
        return contentTypes.get(contentType);
    }

    public Set<String> getContentTypes() {
        return Collections.unmodifiableSet(contentTypes.keySet());
    }

    public void addContentType(String mediaType, ApiSchema schema) {
        if (mediaType != null) {
            this.contentTypes.put(mediaType.trim(), schema != null ? schema : new ApiSchema());
        }
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isRequired() {
        return required;
    }

    public void setRequired(boolean required) {
        this.required = required;
    }

    public Map<String, ApiSchema> getContentTypesMap() {
        return Collections.unmodifiableMap(contentTypes);
    }

    public void setContentTypesMap(Map<String, ApiSchema> contentTypes) {
        this.contentTypes = contentTypes != null ? new LinkedHashMap<>(contentTypes) : new LinkedHashMap<>();
    }

    @Override
    public String toString() {
        return "ApiRequestBody{" +
                "required=" + required +
                ", mediaTypes=" + contentTypes.keySet() +
                '}';
    }
}

