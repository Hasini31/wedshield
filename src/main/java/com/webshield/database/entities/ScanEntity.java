package com.webshield.database.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity representing a security scan execution mapped to table {@code scans}.
 */
@Entity
@Table(name = "scans")
public class ScanEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "website_id", nullable = false)
    private Long websiteId;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "status", nullable = false, length = 32)
    private String status = "QUEUED";

    @Column(name = "crawl_depth", nullable = false)
    private int crawlDepth = 3;

    @Column(name = "max_pages", nullable = false)
    private int maxPages = 50;

    @Column(name = "timeout_seconds", nullable = false)
    private int timeoutSeconds = 15;

    @Column(name = "check_headers", nullable = false)
    private boolean checkHeaders = true;

    @Column(name = "check_cookies", nullable = false)
    private boolean checkCookies = true;

    @Column(name = "check_reflection", nullable = false)
    private boolean checkReflection = true;

    @Column(name = "check_sql_errors", nullable = false)
    private boolean checkSqlErrors = true;

    @Column(name = "check_input_validation", nullable = false)
    private boolean checkInputValidation = true;

    @Column(name = "pages_discovered", nullable = false)
    private int pagesDiscovered = 0;

    @Column(name = "pages_tested", nullable = false)
    private int pagesTested = 0;

    @Column(name = "findings_count", nullable = false)
    private int findingsCount = 0;

    @Column(name = "started_at")
    private LocalDateTime startedAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    public ScanEntity() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getWebsiteId() { return websiteId; }
    public void setWebsiteId(Long websiteId) { this.websiteId = websiteId; }

    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public int getCrawlDepth() { return crawlDepth; }
    public void setCrawlDepth(int crawlDepth) { this.crawlDepth = crawlDepth; }

    public int getMaxPages() { return maxPages; }
    public void setMaxPages(int maxPages) { this.maxPages = maxPages; }

    public int getTimeoutSeconds() { return timeoutSeconds; }
    public void setTimeoutSeconds(int timeoutSeconds) { this.timeoutSeconds = timeoutSeconds; }

    public boolean isCheckHeaders() { return checkHeaders; }
    public void setCheckHeaders(boolean checkHeaders) { this.checkHeaders = checkHeaders; }

    public boolean isCheckCookies() { return checkCookies; }
    public void setCheckCookies(boolean checkCookies) { this.checkCookies = checkCookies; }

    public boolean isCheckReflection() { return checkReflection; }
    public void setCheckReflection(boolean checkReflection) { this.checkReflection = checkReflection; }

    public boolean isCheckSqlErrors() { return checkSqlErrors; }
    public void setCheckSqlErrors(boolean checkSqlErrors) { this.checkSqlErrors = checkSqlErrors; }

    public boolean isCheckInputValidation() { return checkInputValidation; }
    public void setCheckInputValidation(boolean checkInputValidation) { this.checkInputValidation = checkInputValidation; }

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

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}

