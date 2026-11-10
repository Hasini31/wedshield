package com.webshield.database.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity representing generated API security test report metadata mapped to table {@code api_reports}.
 */
@Entity
@Table(name = "api_reports")
public class ApiReportEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "api_scan_id", nullable = false)
    private Long apiScanId;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "report_name", nullable = false, length = 150)
    private String reportName;

    @Column(name = "report_format", nullable = false, length = 16)
    private String reportFormat; // "PDF" or "HTML"

    @Column(name = "file_path", nullable = false, length = 512)
    private String filePath;

    @Column(name = "file_size_bytes", nullable = false)
    private long fileSizeBytes = 0L;

    @Column(name = "has_ai_explanations", nullable = false)
    private boolean hasAiExplanations = false;

    @Column(name = "status", nullable = false, length = 32)
    private String status = "COMPLETED";

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    public ApiReportEntity() {
    }

    public ApiReportEntity(Long apiScanId, Long userId, String reportName, String reportFormat, String filePath, long fileSizeBytes, boolean hasAiExplanations) {
        this.apiScanId = apiScanId;
        this.userId = userId;
        this.reportName = reportName;
        this.reportFormat = reportFormat;
        this.filePath = filePath;
        this.fileSizeBytes = fileSizeBytes;
        this.hasAiExplanations = hasAiExplanations;
        this.status = "COMPLETED";
        this.createdAt = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getApiScanId() {
        return apiScanId;
    }

    public void setApiScanId(Long apiScanId) {
        this.apiScanId = apiScanId;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getReportName() {
        return reportName;
    }

    public void setReportName(String reportName) {
        this.reportName = reportName;
    }

    public String getReportFormat() {
        return reportFormat;
    }

    public void setReportFormat(String reportFormat) {
        this.reportFormat = reportFormat;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public long getFileSizeBytes() {
        return fileSizeBytes;
    }

    public void setFileSizeBytes(long fileSizeBytes) {
        this.fileSizeBytes = fileSizeBytes;
    }

    public boolean isHasAiExplanations() {
        return hasAiExplanations;
    }

    public void setHasAiExplanations(boolean hasAiExplanations) {
        this.hasAiExplanations = hasAiExplanations;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}

