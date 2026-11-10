package com.webshield.crawler;

import java.net.URI;

/**
 * Encapsulates limits and options for a crawling task.
 */
public class CrawlConfiguration {

    private final String targetUrl;
    private final String targetDomain;
    private int maxDepth = 3;
    private int maxPages = 100;
    private int requestTimeoutSeconds = 15;
    private int delayBetweenRequestsMs = 50;
    private boolean allowLocalhost = false;

    public CrawlConfiguration(String targetUrl) {
        if (targetUrl == null || targetUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("Target URL cannot be null or empty.");
        }
        this.targetUrl = targetUrl.trim();
        this.targetDomain = extractDomain(this.targetUrl);
    }

    private static String extractDomain(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            return host != null ? host.toLowerCase() : "";
        } catch (Exception e) {
            return "";
        }
    }

    public String getTargetUrl() { return targetUrl; }
    public String getTargetDomain() { return targetDomain; }

    public int getMaxDepth() { return maxDepth; }
    public CrawlConfiguration setMaxDepth(int maxDepth) {
        this.maxDepth = Math.max(1, maxDepth);
        return this;
    }

    public int getMaxPages() { return maxPages; }
    public CrawlConfiguration setMaxPages(int maxPages) {
        this.maxPages = Math.max(1, maxPages);
        return this;
    }

    public int getRequestTimeoutSeconds() { return requestTimeoutSeconds; }
    public CrawlConfiguration setRequestTimeoutSeconds(int timeout) {
        this.requestTimeoutSeconds = Math.max(1, timeout);
        return this;
    }

    public int getDelayBetweenRequestsMs() { return delayBetweenRequestsMs; }
    public CrawlConfiguration setDelayBetweenRequestsMs(int delayMs) {
        this.delayBetweenRequestsMs = Math.max(0, delayMs);
        return this;
    }

    public boolean isAllowLocalhost() { return allowLocalhost; }
    public CrawlConfiguration setAllowLocalhost(boolean allowLocalhost) {
        this.allowLocalhost = allowLocalhost;
        return this;
    }
}

