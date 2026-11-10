package com.webshield.api.dto;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Data Transfer Object for an API security finding.
 */
public record ApiFindingDto(
        Long id,
        String findingUuid,
        Long scanId,
        Long apiProjectId,
        String executionUuid,
        String ruleId,
        String title,
        String description,
        String severity,
        String confidence,
        String httpMethod,
        String endpointPath,
        String parameterOrField,
        String evidence,
        String cweId,
        String owaspCategory,
        String remediation,
        boolean confirmed,
        String lifecycleStatus,
        LocalDateTime detectedAt
) implements Serializable {}

