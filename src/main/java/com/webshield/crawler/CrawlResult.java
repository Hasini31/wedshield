package com.webshield.crawler;

import java.util.Collections;
import java.util.List;

/**
 * Aggregate summary of a crawling session.
 */
public class CrawlResult {

    private final List<DiscoveredPage> pages;
    private final int totalPages;
    private final int totalForms;
    private final int totalInputs;
    private final long durationMs;
    private final String status;
    private final String targetUrl;

    public CrawlResult(String targetUrl, List<DiscoveredPage> pages, long durationMs, String status) {
        this.targetUrl = targetUrl;
        this.pages = pages != null ? pages : List.of();
        this.totalPages = this.pages.size();

        int formsCount = 0;
        int inputsCount = 0;
        for (DiscoveredPage p : this.pages) {
            formsCount += p.getForms().size();
            for (DiscoveredForm f : p.getForms()) {
                inputsCount += f.getFieldCount();
            }
        }
        this.totalForms = formsCount;
        this.totalInputs = inputsCount;
        this.durationMs = durationMs;
        this.status = status != null ? status : "COMPLETED";
    }

    public String getTargetUrl() { return targetUrl; }
    public List<DiscoveredPage> getPages() { return Collections.unmodifiableList(pages); }
    public int getTotalPages() { return totalPages; }
    public int getTotalForms() { return totalForms; }
    public int getTotalInputs() { return totalInputs; }
    public long getDurationMs() { return durationMs; }
    public String getStatus() { return status; }
}

