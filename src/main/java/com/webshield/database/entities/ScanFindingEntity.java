package com.webshield.database.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity representing a detected security finding mapped to table {@code scan_findings}.
 */
@Entity
@Table(name = "scan_findings")
public class ScanFindingEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "scan_id", nullable = false)
    private Long scanId;

    @Column(name = "vulnerability_id")
    private Integer vulnerabilityId;

    @Column(name = "page_id")
    private Long pageId;

    @Column(name = "severity", nullable = false, length = 32)
    private String severity;

    @Column(name = "status", nullable = false, length = 32)
    private String status = "POTENTIAL";

    @Column(name = "affected_url", nullable = false, length = 2048)
    private String affectedUrl;

    @Column(name = "affected_param", length = 512)
    private String affectedParam;

    @Column(name = "http_method", nullable = false, length = 10)
    private String httpMethod = "GET";

    @Column(name = "finding_name", nullable = false, length = 255)
    private String findingName;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "evidence", columnDefinition = "TEXT")
    private String evidence;

    @Column(name = "detection_method", length = 255)
    private String detectionMethod;

    @Column(name = "request_headers", columnDefinition = "TEXT")
    private String requestHeaders;

    @Column(name = "response_excerpt", columnDefinition = "TEXT")
    private String responseExcerpt;

    @Column(name = "detected_at", nullable = false)
    private LocalDateTime detectedAt = LocalDateTime.now();

    public ScanFindingEntity() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getScanId() { return scanId; }
    public void setScanId(Long scanId) { this.scanId = scanId; }

    public Integer getVulnerabilityId() { return vulnerabilityId; }
    public void setVulnerabilityId(Integer vulnerabilityId) { this.vulnerabilityId = vulnerabilityId; }

    public Long getPageId() { return pageId; }
    public void setPageId(Long pageId) { this.pageId = pageId; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getAffectedUrl() { return affectedUrl; }
    public void setAffectedUrl(String affectedUrl) { this.affectedUrl = affectedUrl; }

    public String getAffectedParam() { return affectedParam; }
    public void setAffectedParam(String affectedParam) { this.affectedParam = affectedParam; }

    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }

    public String getFindingName() { return findingName; }
    public void setFindingName(String findingName) { this.findingName = findingName; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }

    public String getDetectionMethod() { return detectionMethod; }
    public void setDetectionMethod(String detectionMethod) { this.detectionMethod = detectionMethod; }

    public String getRequestHeaders() { return requestHeaders; }
    public void setRequestHeaders(String requestHeaders) { this.requestHeaders = requestHeaders; }

    public String getResponseExcerpt() { return responseExcerpt; }
    public void setResponseExcerpt(String responseExcerpt) { this.responseExcerpt = responseExcerpt; }

    public LocalDateTime getDetectedAt() { return detectedAt; }
    public void setDetectedAt(LocalDateTime detectedAt) { this.detectedAt = detectedAt; }
}

