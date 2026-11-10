package com.webshield.scan;

import com.webshield.assessment.models.Severity;
import com.webshield.models.SecurityFinding;

import java.io.Serializable;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

/**
 * Encapsulates the complete result and summary metrics of a security scan execution.
 */
public class ScanExecutionResult implements Serializable {

    private long scanId;
    private long websiteId;
    private String websiteName;
    private ScanStatus finalStatus;

    private int pagesDiscovered;
    private int pagesTested;
    private int findingsCount;

    private int criticalFindings;
    private int highFindings;
    private int mediumFindings;
    private int lowFindings;
    private int informationalFindings;

    private LocalDateTime startedAt;
    private LocalDateTime completedAt;
    private Duration duration = Duration.ZERO;
    private String errorMessage;

    private List<SecurityFinding> findings = Collections.emptyList();

    public ScanExecutionResult() {}

    public static ScanExecutionResult completed(long scanId, long websiteId, String websiteName,
                                                int pagesDiscovered, int pagesTested,
                                                List<SecurityFinding> findings,
                                                LocalDateTime startedAt, LocalDateTime completedAt) {
        ScanExecutionResult res = new ScanExecutionResult();
        res.scanId = scanId;
        res.websiteId = websiteId;
        res.websiteName = websiteName;
        res.finalStatus = ScanStatus.COMPLETED;
        res.pagesDiscovered = pagesDiscovered;
        res.pagesTested = pagesTested;
        res.startedAt = startedAt;
        res.completedAt = completedAt != null ? completedAt : LocalDateTime.now();
        if (startedAt != null && res.completedAt != null) {
            res.duration = Duration.between(startedAt, res.completedAt);
        }
        res.setFindings(findings != null ? findings : Collections.emptyList());
        return res;
    }

    public static ScanExecutionResult cancelled(long scanId, long websiteId, String websiteName,
                                                int pagesDiscovered, int pagesTested,
                                                LocalDateTime startedAt) {
        ScanExecutionResult res = new ScanExecutionResult();
        res.scanId = scanId;
        res.websiteId = websiteId;
        res.websiteName = websiteName;
        res.finalStatus = ScanStatus.CANCELLED;
        res.pagesDiscovered = pagesDiscovered;
        res.pagesTested = pagesTested;
        res.startedAt = startedAt;
        res.completedAt = LocalDateTime.now();
        if (startedAt != null) {
            res.duration = Duration.between(startedAt, res.completedAt);
        }
        res.errorMessage = "Scan cancelled by operator.";
        return res;
    }

    public static ScanExecutionResult failed(long scanId, long websiteId, String websiteName,
                                             String errorMessage, LocalDateTime startedAt) {
        ScanExecutionResult res = new ScanExecutionResult();
        res.scanId = scanId;
        res.websiteId = websiteId;
        res.websiteName = websiteName;
        res.finalStatus = ScanStatus.FAILED;
        res.errorMessage = errorMessage;
        res.startedAt = startedAt;
        res.completedAt = LocalDateTime.now();
        if (startedAt != null) {
            res.duration = Duration.between(startedAt, res.completedAt);
        }
        return res;
    }

    public void setFindings(List<SecurityFinding> list) {
        this.findings = list;
        this.findingsCount = list.size();
        int crit = 0, high = 0, med = 0, low = 0, info = 0;
        for (SecurityFinding f : list) {
            Severity s = f.getSeverity() != null ? f.getSeverity() : Severity.INFORMATIONAL;
            switch (s) {
                case CRITICAL -> crit++;
                case HIGH -> high++;
                case MEDIUM -> med++;
                case LOW -> low++;
                case INFORMATIONAL -> info++;
            }
        }
        this.criticalFindings = crit;
        this.highFindings = high;
        this.mediumFindings = med;
        this.lowFindings = low;
        this.informationalFindings = info;
    }

    // Getters

    public long getScanId() { return scanId; }
    public long getWebsiteId() { return websiteId; }
    public String getWebsiteName() { return websiteName; }
    public ScanStatus getFinalStatus() { return finalStatus; }
    public int getPagesDiscovered() { return pagesDiscovered; }
    public int getPagesTested() { return pagesTested; }
    public int getFindingsCount() { return findingsCount; }
    public int getCriticalFindings() { return criticalFindings; }
    public int getHighFindings() { return highFindings; }
    public int getMediumFindings() { return mediumFindings; }
    public int getLowFindings() { return lowFindings; }
    public int getInformationalFindings() { return informationalFindings; }
    public LocalDateTime getStartedAt() { return startedAt; }
    public LocalDateTime getCompletedAt() { return completedAt; }
    public Duration getDuration() { return duration; }
    public String getErrorMessage() { return errorMessage; }
    public List<SecurityFinding> getFindings() { return findings; }
}

