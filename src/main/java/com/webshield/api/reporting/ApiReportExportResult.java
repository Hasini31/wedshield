package com.webshield.api.reporting;

import java.io.Serializable;
import java.nio.file.Path;
import java.time.LocalDateTime;

/**
 * Result returned upon generation of a security report file.
 */
public record ApiReportExportResult(
        String reportIdentifier,
        Path filePath,
        String reportFormat,
        long fileSizeBytes,
        LocalDateTime generatedAt,
        boolean success,
        String message
) implements Serializable {

    public static ApiReportExportResult successful(String reportId, Path path, String format, long bytes) {
        return new ApiReportExportResult(reportId, path, format, bytes, LocalDateTime.now(), true, "Report generated successfully.");
    }

    public static ApiReportExportResult failed(String reportId, String format, String message) {
        return new ApiReportExportResult(reportId, null, format, 0L, LocalDateTime.now(), false, message);
    }
}

