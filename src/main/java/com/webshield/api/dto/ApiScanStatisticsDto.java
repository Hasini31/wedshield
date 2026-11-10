package com.webshield.api.dto;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Data Transfer Object for aggregate API scan performance and coverage statistics.
 */
public record ApiScanStatisticsDto(
        Long id,
        Long scanId,
        double avgResponseTimeMs,
        long minResponseTimeMs,
        long maxResponseTimeMs,
        long totalDataTransferredBytes,
        int status2xxCount,
        int status4xxCount,
        int status5xxCount,
        int errorOutcomesCount,
        int objectivesAchieved,
        int totalObjectives,
        double coveragePercentage,
        LocalDateTime calculatedAt
) implements Serializable {}

