package com.webshield.models;

import java.io.Serializable;
import java.util.Objects;

/**
 * Structured container for HTTP request and response evidence verifying a security finding.
 */
public class FindingEvidence implements Serializable {

    private String description;
    private String requestHeaders;
    private String requestBody;
    private String responseHeaders;
    private String responseExcerpt;

    public FindingEvidence() {}

    public FindingEvidence(String description, String responseExcerpt) {
        this.description = description;
        this.responseExcerpt = responseExcerpt;
    }

    public FindingEvidence(String description, String requestHeaders, String responseHeaders, String responseExcerpt) {
        this.description = description;
        this.requestHeaders = requestHeaders;
        this.responseHeaders = responseHeaders;
        this.responseExcerpt = responseExcerpt;
    }

    public String getDescription() {
        return description;
    }

    public FindingEvidence setDescription(String description) {
        this.description = description;
        return this;
    }

    public String getRequestHeaders() {
        return requestHeaders;
    }

    public FindingEvidence setRequestHeaders(String requestHeaders) {
        this.requestHeaders = requestHeaders;
        return this;
    }

    public String getRequestBody() {
        return requestBody;
    }

    public FindingEvidence setRequestBody(String requestBody) {
        this.requestBody = requestBody;
        return this;
    }

    public String getResponseHeaders() {
        return responseHeaders;
    }

    public FindingEvidence setResponseHeaders(String responseHeaders) {
        this.responseHeaders = responseHeaders;
        return this;
    }

    public String getResponseExcerpt() {
        return responseExcerpt;
    }

    public FindingEvidence setResponseExcerpt(String responseExcerpt) {
        this.responseExcerpt = responseExcerpt;
        return this;
    }

    /**
     * Formats a clean unified evidence string for display or legacy persistence.
     */
    public String getFormattedSummary() {
        StringBuilder sb = new StringBuilder();
        if (description != null && !description.isBlank()) {
            sb.append("OBSERVATION: ").append(description.trim()).append("\n\n");
        }
        if (requestHeaders != null && !requestHeaders.isBlank()) {
            sb.append("--- HTTP REQUEST HEADERS ---\n").append(requestHeaders.trim()).append("\n\n");
        }
        if (requestBody != null && !requestBody.isBlank()) {
            sb.append("--- HTTP REQUEST PAYLOAD ---\n").append(requestBody.trim()).append("\n\n");
        }
        if (responseExcerpt != null && !responseExcerpt.isBlank()) {
            sb.append("--- HTTP RESPONSE EXCERPT ---\n").append(responseExcerpt.trim()).append("\n");
        }
        return sb.toString().trim();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FindingEvidence that = (FindingEvidence) o;
        return Objects.equals(description, that.description) &&
                Objects.equals(requestHeaders, that.requestHeaders) &&
                Objects.equals(requestBody, that.requestBody) &&
                Objects.equals(responseExcerpt, that.responseExcerpt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(description, requestHeaders, requestBody, responseExcerpt);
    }

    @Override
    public String toString() {
        return getFormattedSummary();
    }
}

