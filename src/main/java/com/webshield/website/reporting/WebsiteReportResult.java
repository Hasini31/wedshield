package com.webshield.website.reporting;

import com.webshield.database.repositories.ScanRecord;
import com.webshield.models.SecurityFinding;
import com.webshield.models.Website;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * Result container holding the complete generated website security report and scan telemetry.
 */
public record WebsiteReportResult(
        long scanId,
        Website website,
        ScanRecord scanRecord,
        List<SecurityFinding> findings,
        Map<String, Long> severityCounts,
        String reportText,
        LocalDateTime generatedAt,
        String modelName
) implements Serializable {
}
