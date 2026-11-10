package com.webshield.database.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity representing aggregate performance and objective coverage statistics
 * for a completed API scan run mapped to table {@code api_scan_statistics}.
 */
@Entity
@Table(name = "api_scan_statistics")
public class ApiScanStatisticsEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "scan_id", nullable = false, unique = true)
    private Long scanId;

    @Column(name = "avg_response_time_ms", nullable = false)
    private double avgResponseTimeMs = 0.0;

    @Column(name = "min_response_time_ms", nullable = false)
    private long minResponseTimeMs = 0L;

    @Column(name = "max_response_time_ms", nullable = false)
    private long maxResponseTimeMs = 0L;

    @Column(name = "total_data_transferred_bytes", nullable = false)
    private long totalDataTransferredBytes = 0L;

    @Column(name = "status_2xx_count", nullable = false)
    private int status2xxCount = 0;

    @Column(name = "status_4xx_count", nullable = false)
    private int status4xxCount = 0;

    @Column(name = "status_5xx_count", nullable = false)
    private int status5xxCount = 0;

    @Column(name = "error_outcomes_count", nullable = false)
    private int errorOutcomesCount = 0;

    @Column(name = "objectives_achieved", nullable = false)
    private int objectivesAchieved = 0;

    @Column(name = "total_objectives", nullable = false)
    private int totalObjectives = 0;

    @Column(name = "coverage_percentage", nullable = false)
    private double coveragePercentage = 0.0;

    @Column(name = "calculated_at", nullable = false)
    private LocalDateTime calculatedAt = LocalDateTime.now();

    public ApiScanStatisticsEntity() {
    }

    public ApiScanStatisticsEntity(Long scanId) {
        this.scanId = scanId;
        this.calculatedAt = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getScanId() { return scanId; }
    public void setScanId(Long scanId) { this.scanId = scanId; }

    public double getAvgResponseTimeMs() { return avgResponseTimeMs; }
    public void setAvgResponseTimeMs(double avgResponseTimeMs) { this.avgResponseTimeMs = avgResponseTimeMs; }

    public long getMinResponseTimeMs() { return minResponseTimeMs; }
    public void setMinResponseTimeMs(long minResponseTimeMs) { this.minResponseTimeMs = minResponseTimeMs; }

    public long getMaxResponseTimeMs() { return maxResponseTimeMs; }
    public void setMaxResponseTimeMs(long maxResponseTimeMs) { this.maxResponseTimeMs = maxResponseTimeMs; }

    public long getTotalDataTransferredBytes() { return totalDataTransferredBytes; }
    public void setTotalDataTransferredBytes(long totalDataTransferredBytes) { this.totalDataTransferredBytes = totalDataTransferredBytes; }

    public int getStatus2xxCount() { return status2xxCount; }
    public void setStatus2xxCount(int status2xxCount) { this.status2xxCount = status2xxCount; }

    public int getStatus4xxCount() { return status4xxCount; }
    public void setStatus4xxCount(int status4xxCount) { this.status4xxCount = status4xxCount; }

    public int getStatus5xxCount() { return status5xxCount; }
    public void setStatus5xxCount(int status5xxCount) { this.status5xxCount = status5xxCount; }

    public int getErrorOutcomesCount() { return errorOutcomesCount; }
    public void setErrorOutcomesCount(int errorOutcomesCount) { this.errorOutcomesCount = errorOutcomesCount; }

    public int getObjectivesAchieved() { return objectivesAchieved; }
    public void setObjectivesAchieved(int objectivesAchieved) { this.objectivesAchieved = objectivesAchieved; }

    public int getTotalObjectives() { return totalObjectives; }
    public void setTotalObjectives(int totalObjectives) { this.totalObjectives = totalObjectives; }

    public double getCoveragePercentage() { return coveragePercentage; }
    public void setCoveragePercentage(double coveragePercentage) { this.coveragePercentage = coveragePercentage; }

    public LocalDateTime getCalculatedAt() { return calculatedAt; }
    public void setCalculatedAt(LocalDateTime calculatedAt) { this.calculatedAt = calculatedAt; }
}

