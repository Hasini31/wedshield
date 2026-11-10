package com.webshield.api.dto;

import com.webshield.api.models.ApiScanStatus;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Data Transfer Object for API security scan summaries.
 */
public record ApiScanDto(
        Long id,
        Long apiProjectId,
        Long userId,
        String scanName,
        ApiScanStatus status,
        LocalDateTime startedAt,
        LocalDateTime completedAt,
        long durationMs,
        int totalEndpoints,
        int totalGeneratedTestCases,
        int totalExecutedRequests,
        int totalFindings,
        int criticalCount,
        int highCount,
        int mediumCount,
        int lowCount,
        int informationalCount,
        String searchConfigSnapshot,
        String executionConfigSnapshot,
        String terminationReason,
        String errorMessage,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) implements Serializable {}

