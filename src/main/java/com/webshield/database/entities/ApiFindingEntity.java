package com.webshield.database.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity representing a detected API security vulnerability or misconfiguration
 * mapped to table {@code api_findings}.
 */
@Entity
@Table(name = "api_findings")
public class ApiFindingEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "finding_uuid", nullable = false, length = 64)
    private String findingUuid;

    @Column(name = "scan_id", nullable = false)
    private Long scanId;

    @Column(name = "api_project_id", nullable = false)
    private Long apiProjectId;

    @Column(name = "execution_uuid", length = 64)
    private String executionUuid;

    @Column(name = "rule_id", nullable = false, length = 64)
    private String ruleId;

    @Column(name = "title", nullable = false, length = 255)
    private String title;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "severity", nullable = false, length = 32)
    private String severity;

    @Column(name = "confidence", nullable = false, length = 32)
    private String confidence;

    @Column(name = "http_method", nullable = false, length = 16)
    private String httpMethod;

    @Column(name = "endpoint_path", nullable = false, length = 1024)
    private String endpointPath;

    @Column(name = "parameter_or_field", length = 255)
    private String parameterOrField;

    @Column(name = "evidence", columnDefinition = "TEXT")
    private String evidence;

    @Column(name = "cwe_id", nullable = false, length = 32)
    private String cweId;

    @Column(name = "owasp_category", nullable = false, length = 64)
    private String owaspCategory;

    @Column(name = "remediation", columnDefinition = "TEXT")
    private String remediation;

    @Column(name = "is_confirmed", nullable = false)
    private boolean confirmed = false;

    @Column(name = "lifecycle_status", nullable = false, length = 32)
    private String lifecycleStatus = "ACTIVE";

    @Column(name = "detected_at", nullable = false)
    private LocalDateTime detectedAt = LocalDateTime.now();

    public ApiFindingEntity() {
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getFindingUuid() { return findingUuid; }
    public void setFindingUuid(String findingUuid) { this.findingUuid = findingUuid; }

    public Long getScanId() { return scanId; }
    public void setScanId(Long scanId) { this.scanId = scanId; }

    public Long getApiProjectId() { return apiProjectId; }
    public void setApiProjectId(Long apiProjectId) { this.apiProjectId = apiProjectId; }

    public String getExecutionUuid() { return executionUuid; }
    public void setExecutionUuid(String executionUuid) { this.executionUuid = executionUuid; }

    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getConfidence() { return confidence; }
    public void setConfidence(String confidence) { this.confidence = confidence; }

    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }

    public String getEndpointPath() { return endpointPath; }
    public void setEndpointPath(String endpointPath) { this.endpointPath = endpointPath; }

    public String getParameterOrField() { return parameterOrField; }
    public void setParameterOrField(String parameterOrField) { this.parameterOrField = parameterOrField; }

    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }

    public String getCweId() { return cweId; }
    public void setCweId(String cweId) { this.cweId = cweId; }

    public String getOwaspCategory() { return owaspCategory; }
    public void setOwaspCategory(String owaspCategory) { this.owaspCategory = owaspCategory; }

    public String getRemediation() { return remediation; }
    public void setRemediation(String remediation) { this.remediation = remediation; }

    public boolean isConfirmed() { return confirmed; }
    public void setConfirmed(boolean confirmed) { this.confirmed = confirmed; }

    public String getLifecycleStatus() { return lifecycleStatus; }
    public void setLifecycleStatus(String lifecycleStatus) { this.lifecycleStatus = lifecycleStatus; }

    public LocalDateTime getDetectedAt() { return detectedAt; }
    public void setDetectedAt(LocalDateTime detectedAt) { this.detectedAt = detectedAt; }
}

