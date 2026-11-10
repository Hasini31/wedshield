package com.webshield.models;

import java.time.LocalDateTime;

/**
 * Domain model representing an authorized website registered for testing.
 * Maps to the {@code websites} table in MySQL.
 */
public class Website {

    private long id;
    private int userId;
    private String name;
    private String url;
    private String description;
    private boolean authorized;
    private String status; // 'ACTIVE', 'INACTIVE', 'ARCHIVED'
    private LocalDateTime lastScanAt;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Computed / join fields
    private int findingCount;
    private int pageCount;

    public Website() {
        this.status = "ACTIVE";
    }

    public Website(String name, String url) {
        this.name = name;
        this.url = url;
        this.status = "ACTIVE";
    }

    public Website(long id, int userId, String name, String url, String description,
                   boolean authorized, String status, LocalDateTime lastScanAt,
                   LocalDateTime createdAt, LocalDateTime updatedAt) {
        this.id = id;
        this.userId = userId;
        this.name = name;
        this.url = url;
        this.description = description;
        this.authorized = authorized;
        this.status = status != null ? status : "ACTIVE";
        this.lastScanAt = lastScanAt;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    // Getters and Setters
    public long getId() { return id; }
    public void setId(long id) { this.id = id; }

    public int getUserId() { return userId; }
    public void setUserId(int userId) { this.userId = userId; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public boolean isAuthorized() { return authorized; }
    public void setAuthorized(boolean authorized) { this.authorized = authorized; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public LocalDateTime getLastScanAt() { return lastScanAt; }
    public void setLastScanAt(LocalDateTime lastScanAt) { this.lastScanAt = lastScanAt; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }

    public int getFindingCount() { return findingCount; }
    public void setFindingCount(int findingCount) { this.findingCount = findingCount; }

    public int getPageCount() { return pageCount; }
    public void setPageCount(int pageCount) { this.pageCount = pageCount; }

    @Override
    public String toString() {
        return name + " (" + url + ")";
    }
}

