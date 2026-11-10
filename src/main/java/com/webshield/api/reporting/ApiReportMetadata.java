package com.webshield.api.reporting;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Lightweight DTO representing persisted report metadata for display in the UI and history tables.
 */
public record ApiReportMetadata(
        Long id,
        Long apiScanId,
        Long userId,
        String reportName,
        String reportFormat,
        String filePath,
        long fileSizeBytes,
        boolean hasAiExplanations,
        String status,
        LocalDateTime createdAt
) implements Serializable {
}

