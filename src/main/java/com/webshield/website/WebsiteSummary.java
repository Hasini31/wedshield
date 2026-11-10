package com.webshield.website;

import java.time.LocalDateTime;

/**
 * Detailed aggregate summary for a specific registered website.
 */
public class WebsiteSummary {

    private final long websiteId;
    private final String name;
    private final String url;
    private final String description;
    private final boolean authorized;
    private final String status;
    private final LocalDateTime registeredAt;
    private final LocalDateTime lastScanAt;
    private final int totalPages;
    private final int totalForms;
    private final int totalInputFields;
    private final int totalFindings;
    private final String lastScanStatus;

    public WebsiteSummary(long websiteId, String name, String url, String description,
                          boolean authorized, String status, LocalDateTime registeredAt,
                          LocalDateTime lastScanAt, int totalPages, int totalForms,
                          int totalInputFields, int totalFindings, String lastScanStatus) {
        this.websiteId = websiteId;
        this.name = name;
        this.url = url;
        this.description = description;
        this.authorized = authorized;
        this.status = status;
        this.registeredAt = registeredAt;
        this.lastScanAt = lastScanAt;
        this.totalPages = totalPages;
        this.totalForms = totalForms;
        this.totalInputFields = totalInputFields;
        this.totalFindings = totalFindings;
        this.lastScanStatus = lastScanStatus != null ? lastScanStatus : "NOT_SCANNED";
    }

    public long getWebsiteId() { return websiteId; }
    public String getName() { return name; }
    public String getUrl() { return url; }
    public String getDescription() { return description; }
    public boolean isAuthorized() { return authorized; }
    public String getStatus() { return status; }
    public LocalDateTime getRegisteredAt() { return registeredAt; }
    public LocalDateTime getLastScanAt() { return lastScanAt; }
    public int getTotalPages() { return totalPages; }
    public int getTotalForms() { return totalForms; }
    public int getTotalInputFields() { return totalInputFields; }
    public int getTotalFindings() { return totalFindings; }
    public String getLastScanStatus() { return lastScanStatus; }
}

