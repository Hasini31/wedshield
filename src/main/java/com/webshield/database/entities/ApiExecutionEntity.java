package com.webshield.database.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity representing a captured API HTTP dispatch execution mapped to table {@code api_executions}.
 */
@Entity
@Table(name = "api_executions")
public class ApiExecutionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "execution_uuid", nullable = false, length = 64)
    private String executionUuid;

    @Column(name = "scan_id", nullable = false)
    private Long scanId;

    @Column(name = "test_case_id", nullable = false, length = 64)
    private String testCaseId;

    @Column(name = "endpoint", nullable = false, length = 1024)
    private String endpoint;

    @Column(name = "http_method", nullable = false, length = 16)
    private String httpMethod;

    @Column(name = "outcome", nullable = false, length = 32)
    private String outcome;

    @Column(name = "status_code", nullable = false)
    private int statusCode = 0;

    @Column(name = "response_time_ms", nullable = false)
    private long responseTimeMs = 0L;

    @Column(name = "response_size_bytes", nullable = false)
    private long responseSizeBytes = 0L;

    @Column(name = "response_headers", columnDefinition = "TEXT")
    private String responseHeaders;

    @Lob
    @Column(name = "response_body", columnDefinition = "MEDIUMTEXT")
    private String responseBody;

    @Column(name = "is_body_truncated", nullable = false)
    private boolean bodyTruncated = false;

    @Column(name = "is_binary_response", nullable = false)
    private boolean binaryResponse = false;

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    @Column(name = "executed_at", nullable = false)
    private LocalDateTime executedAt = LocalDateTime.now();

    public ApiExecutionEntity() {
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getExecutionUuid() { return executionUuid; }
    public void setExecutionUuid(String executionUuid) { this.executionUuid = executionUuid; }

    public Long getScanId() { return scanId; }
    public void setScanId(Long scanId) { this.scanId = scanId; }

    public String getTestCaseId() { return testCaseId; }
    public void setTestCaseId(String testCaseId) { this.testCaseId = testCaseId; }

    public String getEndpoint() { return endpoint; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }

    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }

    public String getOutcome() { return outcome; }
    public void setOutcome(String outcome) { this.outcome = outcome; }

    public int getStatusCode() { return statusCode; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }

    public long getResponseTimeMs() { return responseTimeMs; }
    public void setResponseTimeMs(long responseTimeMs) { this.responseTimeMs = responseTimeMs; }

    public long getResponseSizeBytes() { return responseSizeBytes; }
    public void setResponseSizeBytes(long responseSizeBytes) { this.responseSizeBytes = responseSizeBytes; }

    public String getResponseHeaders() { return responseHeaders; }
    public void setResponseHeaders(String responseHeaders) { this.responseHeaders = responseHeaders; }

    public String getResponseBody() { return responseBody; }
    public void setResponseBody(String responseBody) { this.responseBody = responseBody; }

    public boolean isBodyTruncated() { return bodyTruncated; }
    public void setBodyTruncated(boolean bodyTruncated) { this.bodyTruncated = bodyTruncated; }

    public boolean isBinaryResponse() { return binaryResponse; }
    public void setBinaryResponse(boolean binaryResponse) { this.binaryResponse = binaryResponse; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    public LocalDateTime getExecutedAt() { return executedAt; }
    public void setExecutedAt(LocalDateTime executedAt) { this.executedAt = executedAt; }
}

