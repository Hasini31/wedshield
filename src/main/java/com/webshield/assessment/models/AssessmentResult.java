package com.webshield.assessment.models;

import java.time.LocalDateTime;

/**
 * Structured security assessment finding result.
 * Maps to the {@code scan_findings} table in MySQL.
 */
public class AssessmentResult {

    private long id;
    private long scanId;
    private Integer vulnerabilityId;
    private Long pageId;

    private final String findingName;
    private final String category;
    private final String vulnerabilityCode;
    private final String affectedUrl;
    private final String affectedParam;
    private final String httpMethod;
    private final Severity severity;
    private final ConfidenceLevel confidence;
    private final String description;
    private final String evidence;
    private final String detectionMethod;
    private final String remediation;
    private final LocalDateTime detectedAt;

    public AssessmentResult(String findingName, String category, String vulnerabilityCode,
                            String affectedUrl, String affectedParam, String httpMethod,
                            Severity severity, ConfidenceLevel confidence, String description,
                            String evidence, String detectionMethod, String remediation) {
        this.findingName = findingName;
        this.category = category;
        this.vulnerabilityCode = vulnerabilityCode;
        this.affectedUrl = affectedUrl;
        this.affectedParam = affectedParam;
        this.httpMethod = httpMethod != null ? httpMethod : "GET";
        this.severity = severity != null ? severity : Severity.INFORMATIONAL;
        this.confidence = confidence != null ? confidence : ConfidenceLevel.POTENTIAL;
        this.description = description;
        this.evidence = evidence;
        this.detectionMethod = detectionMethod;
        this.remediation = remediation;
        this.detectedAt = LocalDateTime.now();
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public long getScanId() { return scanId; }
    public void setScanId(long scanId) { this.scanId = scanId; }

    public Integer getVulnerabilityId() { return vulnerabilityId; }
    public void setVulnerabilityId(Integer vulnerabilityId) { this.vulnerabilityId = vulnerabilityId; }

    public Long getPageId() { return pageId; }
    public void setPageId(Long pageId) { this.pageId = pageId; }

    public String getFindingName() { return findingName; }
    public String getCategory() { return category; }
    public String getVulnerabilityCode() { return vulnerabilityCode; }
    public String getAffectedUrl() { return affectedUrl; }
    public String getAffectedParam() { return affectedParam; }
    public String getHttpMethod() { return httpMethod; }
    public Severity getSeverity() { return severity; }
    public ConfidenceLevel getConfidence() { return confidence; }
    public String getDescription() { return description; }
    public String getEvidence() { return evidence; }
    public String getDetectionMethod() { return detectionMethod; }
    public String getRemediation() { return remediation; }
    public LocalDateTime getDetectedAt() { return detectedAt; }

    @Override
    public String toString() {
        return "[" + severity + "] " + findingName + " at " + affectedUrl;
    }
}

