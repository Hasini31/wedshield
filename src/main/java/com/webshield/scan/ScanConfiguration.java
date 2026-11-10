package com.webshield.scan;

import java.util.Objects;

/**
 * Encapsulates all configuration parameters for executing an automated
 * website security assessment scan.
 */
public class ScanConfiguration {

    private long websiteId;
    private String websiteName;
    private String websiteUrl;
    private int userId;

    private int crawlDepth = 3;
    private int maxPages = 50;
    private int timeoutSeconds = 15;
    private int rateLimitDelayMs = 50;

    // Assessment Categories
    private boolean checkHeaders = true;
    private boolean checkCookies = true;
    private boolean checkReflection = true;
    private boolean checkSqlErrors = true;
    private boolean checkInputValidation = true;

    public ScanConfiguration() {}

    public ScanConfiguration(long websiteId, String websiteName, String websiteUrl, int userId) {
        this.websiteId = websiteId;
        this.websiteName = websiteName;
        this.websiteUrl = websiteUrl;
        this.userId = userId;
    }

    /**
     * Validates configuration parameters and throws {@link IllegalArgumentException}
     * if any parameter is outside acceptable security testing thresholds.
     */
    public void validate() {
        if (websiteId <= 0) {
            throw new IllegalArgumentException("A valid target website must be selected (websiteId > 0).");
        }
        if (websiteUrl == null || websiteUrl.isBlank()) {
            throw new IllegalArgumentException("Target website URL cannot be empty.");
        }
        if (userId <= 0) {
            throw new IllegalArgumentException("Authenticated user ID must be provided.");
        }
        if (crawlDepth < 1 || crawlDepth > 10) {
            throw new IllegalArgumentException("Crawl depth must be between 1 and 10 (specified: " + crawlDepth + ").");
        }
        if (maxPages < 1 || maxPages > 500) {
            throw new IllegalArgumentException("Maximum pages must be between 1 and 500 (specified: " + maxPages + ").");
        }
        if (timeoutSeconds < 1 || timeoutSeconds > 120) {
            throw new IllegalArgumentException("Request timeout must be between 1 and 120 seconds (specified: " + timeoutSeconds + ").");
        }
        if (rateLimitDelayMs < 0 || rateLimitDelayMs > 10000) {
            throw new IllegalArgumentException("Rate limit delay must be between 0 and 10,000 ms (specified: " + rateLimitDelayMs + ").");
        }
        if (!hasAnyCategorySelected()) {
            throw new IllegalArgumentException("At least one security assessment category must be enabled.");
        }
    }

    public boolean hasAnyCategorySelected() {
        return checkHeaders || checkCookies || checkReflection || checkSqlErrors || checkInputValidation;
    }

    // Getters and fluent setters

    public long getWebsiteId() {
        return websiteId;
    }

    public ScanConfiguration setWebsiteId(long websiteId) {
        this.websiteId = websiteId;
        return this;
    }

    public String getWebsiteName() {
        return websiteName;
    }

    public ScanConfiguration setWebsiteName(String websiteName) {
        this.websiteName = websiteName;
        return this;
    }

    public String getWebsiteUrl() {
        return websiteUrl;
    }

    public ScanConfiguration setWebsiteUrl(String websiteUrl) {
        this.websiteUrl = websiteUrl;
        return this;
    }

    public int getUserId() {
        return userId;
    }

    public ScanConfiguration setUserId(int userId) {
        this.userId = userId;
        return this;
    }

    public int getCrawlDepth() {
        return crawlDepth;
    }

    public ScanConfiguration setCrawlDepth(int crawlDepth) {
        this.crawlDepth = crawlDepth;
        return this;
    }

    public int getMaxPages() {
        return maxPages;
    }

    public ScanConfiguration setMaxPages(int maxPages) {
        this.maxPages = maxPages;
        return this;
    }

    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }

    public ScanConfiguration setTimeoutSeconds(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
        return this;
    }

    public int getRateLimitDelayMs() {
        return rateLimitDelayMs;
    }

    public ScanConfiguration setRateLimitDelayMs(int rateLimitDelayMs) {
        this.rateLimitDelayMs = rateLimitDelayMs;
        return this;
    }

    public boolean isCheckHeaders() {
        return checkHeaders;
    }

    public ScanConfiguration setCheckHeaders(boolean checkHeaders) {
        this.checkHeaders = checkHeaders;
        return this;
    }

    public boolean isCheckCookies() {
        return checkCookies;
    }

    public ScanConfiguration setCheckCookies(boolean checkCookies) {
        this.checkCookies = checkCookies;
        return this;
    }

    public boolean isCheckReflection() {
        return checkReflection;
    }

    public ScanConfiguration setCheckReflection(boolean checkReflection) {
        this.checkReflection = checkReflection;
        return this;
    }

    public boolean isCheckSqlErrors() {
        return checkSqlErrors;
    }

    public ScanConfiguration setCheckSqlErrors(boolean checkSqlErrors) {
        this.checkSqlErrors = checkSqlErrors;
        return this;
    }

    public boolean isCheckInputValidation() {
        return checkInputValidation;
    }

    public ScanConfiguration setCheckInputValidation(boolean checkInputValidation) {
        this.checkInputValidation = checkInputValidation;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ScanConfiguration that = (ScanConfiguration) o;
        return websiteId == that.websiteId && userId == that.userId &&
                crawlDepth == that.crawlDepth && maxPages == that.maxPages &&
                timeoutSeconds == that.timeoutSeconds && rateLimitDelayMs == that.rateLimitDelayMs &&
                checkHeaders == that.checkHeaders && checkCookies == that.checkCookies &&
                checkReflection == that.checkReflection && checkSqlErrors == that.checkSqlErrors &&
                checkInputValidation == that.checkInputValidation &&
                Objects.equals(websiteUrl, that.websiteUrl);
    }

    @Override
    public int hashCode() {
        return Objects.hash(websiteId, websiteUrl, userId, crawlDepth, maxPages, timeoutSeconds,
                checkHeaders, checkCookies, checkReflection, checkSqlErrors, checkInputValidation);
    }

    @Override
    public String toString() {
        return "ScanConfiguration{" +
                "websiteId=" + websiteId +
                ", target='" + websiteUrl + '\'' +
                ", depth=" + crawlDepth +
                ", maxPages=" + maxPages +
                ", timeout=" + timeoutSeconds + "s" +
                ", categories=[headers=" + checkHeaders +
                ", cookies=" + checkCookies +
                ", reflection=" + checkReflection +
                ", sql=" + checkSqlErrors +
                ", inputVal=" + checkInputValidation + "]}";
    }
}

