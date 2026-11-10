package com.webshield.api.dto;

import java.io.Serializable;
import java.util.List;

/**
 * Data Transfer Object comparing two historical API scans.
 */
public record ApiScanComparisonDto(
        ApiScanDto scanA,
        ApiScanDto scanB,
        int newFindingsCount,
        int resolvedFindingsCount,
        int persistentFindingsCount,
        double coverageDifference,
        long durationDifferenceMs,
        List<ApiFindingDto> newFindings,
        List<ApiFindingDto> resolvedFindings,
        List<ApiFindingDto> persistentFindings
) implements Serializable {

    public ApiScanComparisonDto(
            ApiScanDto scanA,
            ApiScanDto scanB,
            int newFindingsCount,
            int resolvedFindingsCount,
            int persistentFindingsCount,
            double coverageDifference,
            long durationDifferenceMs,
            List<ApiFindingDto> newFindings,
            List<ApiFindingDto> resolvedFindings
    ) {
        this(scanA, scanB, newFindingsCount, resolvedFindingsCount, persistentFindingsCount,
                coverageDifference, durationDifferenceMs, newFindings, resolvedFindings, List.of());
    }
}

