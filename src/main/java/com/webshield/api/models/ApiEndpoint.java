package com.webshield.api.models;

import java.util.*;

/**
 * Representation of an individual API operation extracted from an OpenAPI specification.
 */
public class ApiEndpoint {

    private String path;
    private HttpMethod method = HttpMethod.GET;
    private String operationId;
    private String summary;
    private String description;
    private List<String> tags = new ArrayList<>();
    private boolean deprecated = false;

    private List<ApiParameter> parameters = new ArrayList<>();
    private ApiRequestBody requestBody;
    private Map<String, ApiResponseSchema> responses = new LinkedHashMap<>();
    private List<ApiSecurityRequirement> securityRequirements = new ArrayList<>();

    public ApiEndpoint() {
    }

    public ApiEndpoint(String path, HttpMethod method) {
        this.path = path;
        this.method = method != null ? method : HttpMethod.GET;
    }

    public String getIdentifier() {
        return (method != null ? method.name() : "GET") + " " + (path != null ? path : "/");
    }

    public boolean hasRequestBody() {
        return requestBody != null;
    }

    public List<ApiParameter> getPathParameters() {
        return parameters.stream()
                .filter(p -> p.getLocation() == ParameterLocation.PATH)
                .toList();
    }

    public List<ApiParameter> getQueryParameters() {
        return parameters.stream()
                .filter(p -> p.getLocation() == ParameterLocation.QUERY)
                .toList();
    }

    public List<ApiParameter> getHeaderParameters() {
        return parameters.stream()
                .filter(p -> p.getLocation() == ParameterLocation.HEADER)
                .toList();
    }

    public List<ApiParameter> getCookieParameters() {
        return parameters.stream()
                .filter(p -> p.getLocation() == ParameterLocation.COOKIE)
                .toList();
    }

    public List<ApiParameter> getRequiredParameters() {
        return parameters.stream()
                .filter(ApiParameter::isRequired)
                .toList();
    }

    public Optional<ApiParameter> getParameter(String name, ParameterLocation location) {
        if (name == null) return Optional.empty();
        return parameters.stream()
                .filter(p -> p.getName() != null && p.getName().equalsIgnoreCase(name) && p.getLocation() == location)
                .findFirst();
    }

    // Getters and Setters
    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public HttpMethod getMethod() {
        return method;
    }

    public void setMethod(HttpMethod method) {
        this.method = method != null ? method : HttpMethod.GET;
    }

    public String getOperationId() {
        return operationId;
    }

    public void setOperationId(String operationId) {
        this.operationId = operationId;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getTags() {
        return Collections.unmodifiableList(tags);
    }

    public void setTags(List<String> tags) {
        this.tags = tags != null ? new ArrayList<>(tags) : new ArrayList<>();
    }

    public void addTag(String tag) {
        if (tag != null && !tag.isBlank()) {
            this.tags.add(tag.trim());
        }
    }

    public boolean isDeprecated() {
        return deprecated;
    }

    public void setDeprecated(boolean deprecated) {
        this.deprecated = deprecated;
    }

    public List<ApiParameter> getParameters() {
        return Collections.unmodifiableList(parameters);
    }

    public void setParameters(List<ApiParameter> parameters) {
        this.parameters = parameters != null ? new ArrayList<>(parameters) : new ArrayList<>();
    }

    public void addParameter(ApiParameter parameter) {
        if (parameter != null) {
            this.parameters.add(parameter);
        }
    }

    public ApiRequestBody getRequestBody() {
        return requestBody;
    }

    public void setRequestBody(ApiRequestBody requestBody) {
        this.requestBody = requestBody;
    }

    public Map<String, ApiResponseSchema> getResponses() {
        return Collections.unmodifiableMap(responses);
    }

    public void setResponses(Map<String, ApiResponseSchema> responses) {
        this.responses = responses != null ? new LinkedHashMap<>(responses) : new LinkedHashMap<>();
    }

    public void addResponse(String statusCode, ApiResponseSchema response) {
        if (statusCode != null && response != null) {
            this.responses.put(statusCode, response);
        }
    }

    public List<ApiSecurityRequirement> getSecurityRequirements() {
        return Collections.unmodifiableList(securityRequirements);
    }

    public void setSecurityRequirements(List<ApiSecurityRequirement> securityRequirements) {
        this.securityRequirements = securityRequirements != null ? new ArrayList<>(securityRequirements) : new ArrayList<>();
    }

    public void addSecurityRequirement(ApiSecurityRequirement requirement) {
        if (requirement != null) {
            this.securityRequirements.add(requirement);
        }
    }

    @Override
    public String toString() {
        return "ApiEndpoint{" +
                "identifier='" + getIdentifier() + '\'' +
                ", parametersCount=" + parameters.size() +
                ", hasRequestBody=" + hasRequestBody() +
                ", responsesCount=" + responses.size() +
                '}';
    }
}

