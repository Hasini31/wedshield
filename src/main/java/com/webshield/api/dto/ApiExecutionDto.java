package com.webshield.api.dto;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Data Transfer Object for an API request execution observation.
 */
public record ApiExecutionDto(
        Long id,
        String executionUuid,
        Long scanId,
        String testCaseId,
        String endpoint,
        String httpMethod,
        String outcome,
        int statusCode,
        long responseTimeMs,
        long responseSizeBytes,
        String responseHeaders,
        String responseBody,
        boolean bodyTruncated,
        boolean binaryResponse,
        String errorMessage,
        LocalDateTime executedAt
) implements Serializable {}

