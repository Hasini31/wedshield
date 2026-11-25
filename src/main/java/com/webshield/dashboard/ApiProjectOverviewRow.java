package com.webshield.dashboard;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Data model for the API Projects table on the Dashboard.
 * Encapsulates project identity, specification format, test execution statistics,
 * and vulnerability counts across all severities for interactive charting.
 */
public class ApiProjectOverviewRow {

    private final long   id;
    private final String name;
    private final String specDisplay;
    private final int    endpointsCount;
    private final int    scansRun;
    private final int    testCasesGenerated;
    private final int    requestsExecuted;
    private final int    totalFindings;
    private final int    criticalFindings;
    private final int    highFindings;
    private final int    mediumFindings;
    private final int    lowFindings;
    private final int    infoFindings;
    private final String lastScanDate;
    private final String status;
    private final Long   lastScanId;

    public ApiProjectOverviewRow(long id, String name, String specDisplay, int endpointsCount,
                                 int scansRun, int testCasesGenerated, int requestsExecuted,
                                 int totalFindings, int criticalFindings, int highFindings,
                                 int mediumFindings, int lowFindings, int infoFindings,
                                 String lastScanDate, String status, Long lastScanId) {
        this.id                 = id;
        this.name               = name;
        this.specDisplay        = specDisplay;
        this.endpointsCount     = endpointsCount;
        this.scansRun           = scansRun;
        this.testCasesGenerated = testCasesGenerated;
        this.requestsExecuted   = requestsExecuted;
        this.totalFindings      = totalFindings;
        this.criticalFindings   = criticalFindings;
        this.highFindings       = highFindings;
        this.mediumFindings     = mediumFindings;
        this.lowFindings        = lowFindings;
        this.infoFindings       = infoFindings;
        this.lastScanDate       = lastScanDate;
        this.status             = status;
        this.lastScanId         = lastScanId;
    }

    public long   getId()                 { return id; }
    public String getName()               { return name; }
    public String getSpecDisplay()        { return specDisplay; }
    public int    getEndpointsCount()     { return endpointsCount; }
    public int    getScansRun()           { return scansRun; }
    public int    getTestCasesGenerated() { return testCasesGenerated; }
    public int    getRequestsExecuted()   { return requestsExecuted; }
    public int    getTotalFindings()      { return totalFindings; }
    public int    getCriticalFindings()   { return criticalFindings; }
    public int    getHighFindings()       { return highFindings; }
    public int    getMediumFindings()     { return mediumFindings; }
    public int    getLowFindings()        { return lowFindings; }
    public int    getInfoFindings()       { return infoFindings; }
    public String getLastScanDate()       { return lastScanDate; }
    public String getStatus()             { return status; }
    public Long   getLastScanId()         { return lastScanId; }

    /**
     * Returns an ordered map of vulnerability counts by severity for this project.
     */
    public Map<String, Integer> getFindingsBySeverity() {
        Map<String, Integer> map = new LinkedHashMap<>();
        map.put("CRITICAL", criticalFindings);
        map.put("HIGH", highFindings);
        map.put("MEDIUM", mediumFindings);
        map.put("LOW", lowFindings);
        map.put("INFORMATIONAL", infoFindings);
        return map;
    }
}
