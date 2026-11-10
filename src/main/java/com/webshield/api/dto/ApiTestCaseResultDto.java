package com.webshield.api.dto;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Data Transfer Object for an API test case definition and lineage.
 */
public record ApiTestCaseResultDto(
        Long id,
        Long scanId,
        String testCaseId,
        String endpointIdentifier,
        String httpMethod,
        String category,
        String strategy,
        String parentTestCaseId,
        String targetedProperty,
        String targetedConstraint,
        String description,
        LocalDateTime createdAt
) implements Serializable {}

