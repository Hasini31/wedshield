package com.webshield.api.dto;

import com.webshield.database.entities.*;

import java.util.Collections;
import java.util.List;

/**
 * Mapper for converting between JPA entities and clean DTO records.
 */
public final class ApiPersistenceMapper {

    private ApiPersistenceMapper() {}

    public static ApiScanDto toDto(ApiScanEntity entity) {
        if (entity == null) return null;
        return new ApiScanDto(
                entity.getId(),
                entity.getApiProjectId(),
                entity.getUserId(),
                entity.getScanName(),
                entity.getStatus(),
                entity.getStartedAt(),
                entity.getCompletedAt(),
                entity.getDurationMs(),
                entity.getTotalEndpoints(),
                entity.getTotalGeneratedTestCases(),
                entity.getTotalExecutedRequests(),
                entity.getTotalFindings(),
                entity.getCriticalCount(),
                entity.getHighCount(),
                entity.getMediumCount(),
                entity.getLowCount(),
                entity.getInformationalCount(),
                entity.getSearchConfigSnapshot(),
                entity.getExecutionConfigSnapshot(),
                entity.getTerminationReason(),
                entity.getErrorMessage(),
                entity.getCreatedAt(),
                entity.getUpdatedAt()
        );
    }

    public static List<ApiScanDto> toScanDtos(List<ApiScanEntity> entities) {
        if (entities == null || entities.isEmpty()) return Collections.emptyList();
        return entities.stream().map(ApiPersistenceMapper::toDto).toList();
    }

    public static ApiExecutionDto toDto(ApiExecutionEntity entity) {
        if (entity == null) return null;
        return new ApiExecutionDto(
                entity.getId(),
                entity.getExecutionUuid(),
                entity.getScanId(),
                entity.getTestCaseId(),
                entity.getEndpoint(),
                entity.getHttpMethod(),
                entity.getOutcome(),
                entity.getStatusCode(),
                entity.getResponseTimeMs(),
                entity.getResponseSizeBytes(),
                entity.getResponseHeaders(),
                entity.getResponseBody(),
                entity.isBodyTruncated(),
                entity.isBinaryResponse(),
                entity.getErrorMessage(),
                entity.getExecutedAt()
        );
    }

    public static List<ApiExecutionDto> toExecutionDtos(List<ApiExecutionEntity> entities) {
        if (entities == null || entities.isEmpty()) return Collections.emptyList();
        return entities.stream().map(ApiPersistenceMapper::toDto).toList();
    }

    public static ApiFindingDto toDto(ApiFindingEntity entity) {
        if (entity == null) return null;
        return new ApiFindingDto(
                entity.getId(),
                entity.getFindingUuid(),
                entity.getScanId(),
                entity.getApiProjectId(),
                entity.getExecutionUuid(),
                entity.getRuleId(),
                entity.getTitle(),
                entity.getDescription(),
                entity.getSeverity(),
                entity.getConfidence(),
                entity.getHttpMethod(),
                entity.getEndpointPath(),
                entity.getParameterOrField(),
                entity.getEvidence(),
                entity.getCweId(),
                entity.getOwaspCategory(),
                entity.getRemediation(),
                entity.isConfirmed(),
                entity.getLifecycleStatus(),
                entity.getDetectedAt()
        );
    }

    public static List<ApiFindingDto> toFindingDtos(List<ApiFindingEntity> entities) {
        if (entities == null || entities.isEmpty()) return Collections.emptyList();
        return entities.stream().map(ApiPersistenceMapper::toDto).toList();
    }

    public static ApiTestCaseResultDto toDto(ApiTestCaseResultEntity entity) {
        if (entity == null) return null;
        return new ApiTestCaseResultDto(
                entity.getId(),
                entity.getScanId(),
                entity.getTestCaseId(),
                entity.getEndpointIdentifier(),
                entity.getHttpMethod(),
                entity.getCategory(),
                entity.getStrategy(),
                entity.getParentTestCaseId(),
                entity.getTargetedProperty(),
                entity.getTargetedConstraint(),
                entity.getDescription(),
                entity.getCreatedAt()
        );
    }

    public static List<ApiTestCaseResultDto> toTestCaseDtos(List<ApiTestCaseResultEntity> entities) {
        if (entities == null || entities.isEmpty()) return Collections.emptyList();
        return entities.stream().map(ApiPersistenceMapper::toDto).toList();
    }

    public static ApiScanStatisticsDto toDto(ApiScanStatisticsEntity entity) {
        if (entity == null) return null;
        return new ApiScanStatisticsDto(
                entity.getId(),
                entity.getScanId(),
                entity.getAvgResponseTimeMs(),
                entity.getMinResponseTimeMs(),
                entity.getMaxResponseTimeMs(),
                entity.getTotalDataTransferredBytes(),
                entity.getStatus2xxCount(),
                entity.getStatus4xxCount(),
                entity.getStatus5xxCount(),
                entity.getErrorOutcomesCount(),
                entity.getObjectivesAchieved(),
                entity.getTotalObjectives(),
                entity.getCoveragePercentage(),
                entity.getCalculatedAt()
        );
    }
}

