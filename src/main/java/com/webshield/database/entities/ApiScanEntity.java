package com.webshield.database.entities;

import com.webshield.api.models.ApiScanStatus;
import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity representing an automated API security scan run mapped to table {@code api_scans}.
 */
@Entity
@Table(name = "api_scans")
public class ApiScanEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "api_project_id", nullable = false)
    private Long apiProjectId;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "scan_name", nullable = false, length = 150)
    private String scanName;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    private ApiScanStatus status = ApiScanStatus.PENDING;

    @Column(name = "started_at")
    private LocalDateTime startedAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @Column(name = "duration_ms", nullable = false)
    private long durationMs = 0L;

    @Column(name = "total_endpoints", nullable = false)
    private int totalEndpoints = 0;

    @Column(name = "total_generated_test_cases", nullable = false)
    private int totalGeneratedTestCases = 0;

    @Column(name = "total_executed_requests", nullable = false)
    private int totalExecutedRequests = 0;

    @Column(name = "total_findings", nullable = false)
    private int totalFindings = 0;

    @Column(name = "critical_count", nullable = false)
    private int criticalCount = 0;

    @Column(name = "high_count", nullable = false)
    private int highCount = 0;

    @Column(name = "medium_count", nullable = false)
    private int mediumCount = 0;

    @Column(name = "low_count", nullable = false)
    private int lowCount = 0;

    @Column(name = "informational_count", nullable = false)
    private int informationalCount = 0;

    @Column(name = "search_config_snapshot", columnDefinition = "TEXT")
    private String searchConfigSnapshot;

    @Column(name = "execution_config_snapshot", columnDefinition = "TEXT")
    private String executionConfigSnapshot;

    @Column(name = "termination_reason", length = 64)
    private String terminationReason;

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt = LocalDateTime.now();

    public ApiScanEntity() {
    }

    public ApiScanEntity(Long apiProjectId, Long userId, String scanName) {
        this.apiProjectId = apiProjectId;
        this.userId = userId;
        this.scanName = scanName;
        this.status = ApiScanStatus.PENDING;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    public void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getApiProjectId() { return apiProjectId; }
    public void setApiProjectId(Long apiProjectId) { this.apiProjectId = apiProjectId; }

    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }

    public String getScanName() { return scanName; }
    public void setScanName(String scanName) { this.scanName = scanName; }

    public ApiScanStatus getStatus() { return status; }
    public void setStatus(ApiScanStatus status) { this.status = status; }

    public LocalDateTime getStartedAt() { return startedAt; }
    public void setStartedAt(LocalDateTime startedAt) { this.startedAt = startedAt; }

    public LocalDateTime getCompletedAt() { return completedAt; }
    public void setCompletedAt(LocalDateTime completedAt) { this.completedAt = completedAt; }

    public long getDurationMs() { return durationMs; }
    public void setDurationMs(long durationMs) { this.durationMs = durationMs; }

    public int getTotalEndpoints() { return totalEndpoints; }
    public void setTotalEndpoints(int totalEndpoints) { this.totalEndpoints = totalEndpoints; }

    public int getTotalGeneratedTestCases() { return totalGeneratedTestCases; }
    public void setTotalGeneratedTestCases(int totalGeneratedTestCases) { this.totalGeneratedTestCases = totalGeneratedTestCases; }

    public int getTotalExecutedRequests() { return totalExecutedRequests; }
    public void setTotalExecutedRequests(int totalExecutedRequests) { this.totalExecutedRequests = totalExecutedRequests; }

    public int getTotalFindings() { return totalFindings; }
    public void setTotalFindings(int totalFindings) { this.totalFindings = totalFindings; }

    public int getCriticalCount() { return criticalCount; }
    public void setCriticalCount(int criticalCount) { this.criticalCount = criticalCount; }

    public int getHighCount() { return highCount; }
    public void setHighCount(int highCount) { this.highCount = highCount; }

    public int getMediumCount() { return mediumCount; }
    public void setMediumCount(int mediumCount) { this.mediumCount = mediumCount; }

    public int getLowCount() { return lowCount; }
    public void setLowCount(int lowCount) { this.lowCount = lowCount; }

    public int getInformationalCount() { return informationalCount; }
    public void setInformationalCount(int informationalCount) { this.informationalCount = informationalCount; }

    public String getSearchConfigSnapshot() { return searchConfigSnapshot; }
    public void setSearchConfigSnapshot(String searchConfigSnapshot) { this.searchConfigSnapshot = searchConfigSnapshot; }

    public String getExecutionConfigSnapshot() { return executionConfigSnapshot; }
    public void setExecutionConfigSnapshot(String executionConfigSnapshot) { this.executionConfigSnapshot = executionConfigSnapshot; }

    public String getTerminationReason() { return terminationReason; }
    public void setTerminationReason(String terminationReason) { this.terminationReason = terminationReason; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
}

