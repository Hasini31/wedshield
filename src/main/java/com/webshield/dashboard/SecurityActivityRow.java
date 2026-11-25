package com.webshield.dashboard;

/**
 * Data model for the unified Recent Security Activity table combining website and API scans.
 */
public class SecurityActivityRow {
    private final long   rawScanId;
    private final String displayId;
    private final String targetName;
    private final String targetType; // "WEBSITE" or "API"
    private final String scanDate;
    private final String duration;
    private final String unitsTested; // e.g. "45 pages" or "129 reqs"
    private final int    findingsCount;
    private final String scanStatus;

    public SecurityActivityRow(long rawScanId, String displayId, String targetName,
                               String targetType, String scanDate, String duration,
                               String unitsTested, int findingsCount, String scanStatus) {
        this.rawScanId      = rawScanId;
        this.displayId      = displayId;
        this.targetName     = targetName;
        this.targetType     = targetType;
        this.scanDate       = scanDate;
        this.duration       = duration;
        this.unitsTested    = unitsTested;
        this.findingsCount  = findingsCount;
        this.scanStatus     = scanStatus;
    }

    public long   getRawScanId()     { return rawScanId; }
    public String getDisplayId()     { return displayId; }
    public String getTargetName()    { return targetName; }
    public String getTargetType()    { return targetType; }
    public String getScanDate()      { return scanDate; }
    public String getDuration()      { return duration; }
    public String getUnitsTested()   { return unitsTested; }
    public int    getFindingsCount() { return findingsCount; }
    public String getScanStatus()    { return scanStatus; }
}

