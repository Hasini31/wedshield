package com.webshield.api.models;

import java.util.*;

/**
 * Result of complete OpenAPI specification parsing and endpoint extraction.
 */
public class ParsedApiSpecification {

    private OpenApiMetadata metadata = new OpenApiMetadata();
    private List<ApiEndpoint> endpoints = new ArrayList<>();
    private List<String> warnings = new ArrayList<>();
    private List<String> errors = new ArrayList<>();
    private String rawSpecification;

    public ParsedApiSpecification() {
    }

    public ParsedApiSpecification(OpenApiMetadata metadata, List<ApiEndpoint> endpoints,
                                  List<String> warnings, List<String> errors, String rawSpecification) {
        this.metadata = metadata != null ? metadata : new OpenApiMetadata();
        this.endpoints = endpoints != null ? new ArrayList<>(endpoints) : new ArrayList<>();
        this.warnings = warnings != null ? new ArrayList<>(warnings) : new ArrayList<>();
        this.errors = errors != null ? new ArrayList<>(errors) : new ArrayList<>();
        this.rawSpecification = rawSpecification;
    }

    public int getEndpointsCount() {
        return endpoints.size();
    }

    public Optional<ApiEndpoint> findEndpoint(String path, HttpMethod method) {
        if (path == null || method == null) {
            return Optional.empty();
        }
        return endpoints.stream()
                .filter(e -> e.getMethod() == method && path.equalsIgnoreCase(e.getPath()))
                .findFirst();
    }

    public List<ApiEndpoint> findEndpointsByTag(String tag) {
        if (tag == null || tag.isBlank()) {
            return List.of();
        }
        String lowerTag = tag.trim().toLowerCase(Locale.ROOT);
        return endpoints.stream()
                .filter(e -> e.getTags().stream().anyMatch(t -> t.toLowerCase(Locale.ROOT).equals(lowerTag)))
                .toList();
    }

    public OpenApiMetadata getMetadata() {
        return metadata;
    }

    public void setMetadata(OpenApiMetadata metadata) {
        this.metadata = metadata != null ? metadata : new OpenApiMetadata();
    }

    public List<ApiEndpoint> getEndpoints() {
        return Collections.unmodifiableList(endpoints);
    }

    public void setEndpoints(List<ApiEndpoint> endpoints) {
        this.endpoints = endpoints != null ? new ArrayList<>(endpoints) : new ArrayList<>();
    }

    public void addEndpoint(ApiEndpoint endpoint) {
        if (endpoint != null) {
            this.endpoints.add(endpoint);
        }
    }

    public List<String> getWarnings() {
        return Collections.unmodifiableList(warnings);
    }

    public void setWarnings(List<String> warnings) {
        this.warnings = warnings != null ? new ArrayList<>(warnings) : new ArrayList<>();
    }

    public void addWarning(String warning) {
        if (warning != null) {
            this.warnings.add(warning);
        }
    }

    public List<String> getErrors() {
        return Collections.unmodifiableList(errors);
    }

    public void setErrors(List<String> errors) {
        this.errors = errors != null ? new ArrayList<>(errors) : new ArrayList<>();
    }

    public void addError(String error) {
        if (error != null) {
            this.errors.add(error);
        }
    }

    public String getRawSpecification() {
        return rawSpecification;
    }

    public void setRawSpecification(String rawSpecification) {
        this.rawSpecification = rawSpecification;
    }

    @Override
    public String toString() {
        return "ParsedApiSpecification{" +
                "title='" + metadata.getTitle() + '\'' +
                ", endpointsCount=" + endpoints.size() +
                ", warningsCount=" + warnings.size() +
                ", errorsCount=" + errors.size() +
                '}';
    }
}

