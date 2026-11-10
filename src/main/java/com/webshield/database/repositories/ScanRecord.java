package com.webshield.database.repositories;

import java.time.LocalDateTime;

/**
 * Model representing an assessment scan run record.
 */
public class ScanRecord {

    private long id;
    private long websiteId;
    private String websiteName;
    private int userId;
    private String status;
    private int crawlDepth;
    private int maxPages;
    private int timeoutSeconds;
    private int pagesDiscovered;
    private int pagesTested;
    private int findingsCount;
    private LocalDateTime startedAt;
    private LocalDateTime completedAt;
    private LocalDateTime createdAt;

    public ScanRecord() {}

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public long getWebsiteId() { return websiteId; }
    public void setWebsiteId(long websiteId) { this.websiteId = websiteId; }

    public String getWebsiteName() { return websiteName; }
    public void setWebsiteName(String websiteName) { this.websiteName = websiteName; }

    public int getUserId() { return userId; }
    public void setUserId(int userId) { this.userId = userId; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public int getCrawlDepth() { return crawlDepth; }
    public void setCrawlDepth(int crawlDepth) { this.crawlDepth = crawlDepth; }

    public int getMaxPages() { return maxPages; }
    public void setMaxPages(int maxPages) { this.maxPages = maxPages; }

    public int getTimeoutSeconds() { return timeoutSeconds; }
    public void setTimeoutSeconds(int timeoutSeconds) { this.timeoutSeconds = timeoutSeconds; }

    public int getPagesDiscovered() { return pagesDiscovered; }
    public void setPagesDiscovered(int pagesDiscovered) { this.pagesDiscovered = pagesDiscovered; }

    public int getPagesTested() { return pagesTested; }
    public void setPagesTested(int pagesTested) { this.pagesTested = pagesTested; }

    public int getFindingsCount() { return findingsCount; }
    public void setFindingsCount(int findingsCount) { this.findingsCount = findingsCount; }

    public LocalDateTime getStartedAt() { return startedAt; }
    public void setStartedAt(LocalDateTime startedAt) { this.startedAt = startedAt; }

    public LocalDateTime getCompletedAt() { return completedAt; }
    public void setCompletedAt(LocalDateTime completedAt) { this.completedAt = completedAt; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}

