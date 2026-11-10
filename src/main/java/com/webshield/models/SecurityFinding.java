package com.webshield.models;

import com.webshield.assessment.models.AssessmentResult;
import com.webshield.assessment.models.ConfidenceLevel;
import com.webshield.assessment.models.Severity;
import com.webshield.findings.FindingStatus;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Domain model representing a verified or potential security finding detected during an assessment scan.
 */
public class SecurityFinding implements Serializable {

    private long id;
    private long scanId;
    private long websiteId;
    private String websiteName;
    private Integer vulnerabilityId;
    private String vulnerabilityCode;
    private String findingName;
    private String category;
    private String affectedUrl;
    private String affectedParam;
    private String httpMethod = "GET";
    private Severity severity = Severity.INFORMATIONAL;
    private ConfidenceLevel confidenceLevel = ConfidenceLevel.POTENTIAL;
    private FindingStatus findingStatus = FindingStatus.OPEN;

    private FindingEvidence evidence = new FindingEvidence();
    private String description;
    private String remediation;
    private String detectionMethod;
    private LocalDateTime detectedAt = LocalDateTime.now();

    public SecurityFinding() {}

    public SecurityFinding(String findingName, String category, String affectedUrl, Severity severity) {
        this.findingName = findingName;
        this.category = category;
        this.affectedUrl = affectedUrl;
        this.severity = severity;
    }

    /**
     * Converts an {@link AssessmentResult} into a standardized {@link SecurityFinding}.
     */
    public static SecurityFinding fromAssessmentResult(AssessmentResult ar, long websiteId, String websiteName) {
        SecurityFinding sf = new SecurityFinding();
        sf.setId(ar.getId());
        sf.setScanId(ar.getScanId());
        sf.setWebsiteId(websiteId);
        sf.setWebsiteName(websiteName);
        sf.setVulnerabilityId(ar.getVulnerabilityId() != null && ar.getVulnerabilityId() > 0 ? ar.getVulnerabilityId() : null);
        sf.setVulnerabilityCode(ar.getVulnerabilityCode());
        sf.setFindingName(ar.getFindingName());
        sf.setCategory(ar.getCategory());
        sf.setAffectedUrl(ar.getAffectedUrl());
        sf.setAffectedParam(ar.getAffectedParam());
        sf.setHttpMethod(ar.getHttpMethod() != null ? ar.getHttpMethod() : "GET");
        sf.setSeverity(ar.getSeverity() != null ? ar.getSeverity() : Severity.INFORMATIONAL);
        sf.setConfidenceLevel(ar.getConfidence() != null ? ar.getConfidence() : ConfidenceLevel.POTENTIAL);
        sf.setFindingStatus(FindingStatus.OPEN);

        FindingEvidence ev = new FindingEvidence();
        ev.setDescription(ar.getEvidence());
        sf.setEvidence(ev);

        sf.setDescription(ar.getDescription());
        sf.setRemediation(ar.getRemediation());
        sf.setDetectionMethod(ar.getDetectionMethod());
        sf.setDetectedAt(ar.getDetectedAt() != null ? ar.getDetectedAt() : LocalDateTime.now());
        return sf;
    }

    /**
     * Converts this {@link SecurityFinding} into an {@link AssessmentResult} for legacy consumers.
     */
    public AssessmentResult toAssessmentResult() {
        AssessmentResult ar = new AssessmentResult(
                findingName,
                category != null ? category : "Vulnerability",
                vulnerabilityCode != null ? vulnerabilityCode : "WS-GEN-001",
                affectedUrl,
                affectedParam,
                httpMethod,
                severity,
                confidenceLevel,
                description,
                evidence != null ? evidence.getFormattedSummary() : "",
                detectionMethod,
                remediation
        );
        ar.setId(id);
        ar.setScanId(scanId);
        if (vulnerabilityId != null) ar.setVulnerabilityId(vulnerabilityId);
        return ar;
    }

    // Getters and Setters

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public long getScanId() { return scanId; }
    public void setScanId(long scanId) { this.scanId = scanId; }

    public long getWebsiteId() { return websiteId; }
    public void setWebsiteId(long websiteId) { this.websiteId = websiteId; }

    public String getWebsiteName() { return websiteName; }
    public void setWebsiteName(String websiteName) { this.websiteName = websiteName; }

    public Integer getVulnerabilityId() { return vulnerabilityId; }
    public void setVulnerabilityId(Integer vulnerabilityId) { this.vulnerabilityId = vulnerabilityId; }

    public String getVulnerabilityCode() { return vulnerabilityCode; }
    public void setVulnerabilityCode(String vulnerabilityCode) { this.vulnerabilityCode = vulnerabilityCode; }

    public String getFindingName() { return findingName; }
    public void setFindingName(String findingName) { this.findingName = findingName; }

    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }

    public String getAffectedUrl() { return affectedUrl; }
    public void setAffectedUrl(String affectedUrl) { this.affectedUrl = affectedUrl; }

    public String getAffectedParam() { return affectedParam; }
    public void setAffectedParam(String affectedParam) { this.affectedParam = affectedParam; }

    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }

    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity != null ? severity : Severity.INFORMATIONAL; }

    public ConfidenceLevel getConfidenceLevel() { return confidenceLevel; }
    public void setConfidenceLevel(ConfidenceLevel confidenceLevel) {
        this.confidenceLevel = confidenceLevel != null ? confidenceLevel : ConfidenceLevel.POTENTIAL;
    }

    public FindingStatus getFindingStatus() { return findingStatus; }
    public void setFindingStatus(FindingStatus findingStatus) {
        this.findingStatus = findingStatus != null ? findingStatus : FindingStatus.OPEN;
    }

    public FindingEvidence getEvidence() { return evidence; }
    public void setEvidence(FindingEvidence evidence) { this.evidence = evidence; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getRemediation() { return remediation; }
    public void setRemediation(String remediation) { this.remediation = remediation; }

    public String getDetectionMethod() { return detectionMethod; }
    public void setDetectionMethod(String detectionMethod) { this.detectionMethod = detectionMethod; }

    public LocalDateTime getDetectedAt() { return detectedAt; }
    public void setDetectedAt(LocalDateTime detectedAt) { this.detectedAt = detectedAt; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityFinding that = (SecurityFinding) o;
        return scanId == that.scanId &&
                Objects.equals(affectedUrl, that.affectedUrl) &&
                Objects.equals(affectedParam, that.affectedParam) &&
                Objects.equals(findingName, that.findingName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(scanId, affectedUrl, affectedParam, findingName);
    }

    @Override
    public String toString() {
        return "[" + severity + "] " + findingName + " (" + affectedUrl +
                (affectedParam != null ? "?" + affectedParam : "") + ") - " + findingStatus;
    }
}
