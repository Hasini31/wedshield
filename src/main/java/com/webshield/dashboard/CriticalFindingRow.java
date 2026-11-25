package com.webshield.dashboard;

/**
 * Data model for the Critical Security Findings table on the Dashboard.
 */
public class CriticalFindingRow {
    private final long   findingId;
    private final String findingName;
    private final String target;
    private final String targetType; // "WEBSITE" or "API"
    private final String category;
    private final String severity;
    private final String confidence;
    private final String reviewStatus;
    private final long   scanId;

    public CriticalFindingRow(long findingId, String findingName, String target,
                              String targetType, String category, String severity,
                              String confidence, String reviewStatus, long scanId) {
        this.findingId     = findingId;
        this.findingName   = findingName;
        this.target        = target;
        this.targetType    = targetType;
        this.category      = category;
        this.severity      = severity;
        this.confidence    = confidence;
        this.reviewStatus  = reviewStatus;
        this.scanId        = scanId;
    }

    public long   getFindingId()    { return findingId; }
    public String getFindingName()  { return findingName; }
    public String getTarget()       { return target; }
    public String getTargetType()   { return targetType; }
    public String getCategory()     { return category; }
    public String getSeverity()     { return severity; }
    public String getConfidence()   { return confidence; }
    public String getReviewStatus() { return reviewStatus; }
    public long   getScanId()       { return scanId; }
}

