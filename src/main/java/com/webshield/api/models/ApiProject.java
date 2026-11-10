package com.webshield.api.models;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Domain model representing an API security testing project.
 */
public class ApiProject {

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    private Long id;
    private Long userId;
    private String name;
    private String description;
    private SpecType specType = SpecType.OPENAPI_3;
    private SpecFormat specFormat = SpecFormat.JSON;
    private SourceType sourceType = SourceType.FILE_UPLOAD;
    private String sourceUrl;
    private String rawSpecification;
    private int endpointsCount;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public ApiProject() {
    }

    public ApiProject(Long id, Long userId, String name, String description,
                      SpecType specType, SpecFormat specFormat, SourceType sourceType,
                      String sourceUrl, String rawSpecification, int endpointsCount,
                      LocalDateTime createdAt, LocalDateTime updatedAt) {
        this.id = id;
        this.userId = userId;
        this.name = name;
        this.description = description;
        this.specType = specType;
        this.specFormat = specFormat;
        this.sourceType = sourceType;
        this.sourceUrl = sourceUrl;
        this.rawSpecification = rawSpecification;
        this.endpointsCount = endpointsCount;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public SpecType getSpecType() {
        return specType;
    }

    public void setSpecType(SpecType specType) {
        this.specType = specType;
    }

    public SpecFormat getSpecFormat() {
        return specFormat;
    }

    public void setSpecFormat(SpecFormat specFormat) {
        this.specFormat = specFormat;
    }

    public SourceType getSourceType() {
        return sourceType;
    }

    public void setSourceType(SourceType sourceType) {
        this.sourceType = sourceType;
    }

    public String getSourceUrl() {
        return sourceUrl;
    }

    public void setSourceUrl(String sourceUrl) {
        this.sourceUrl = sourceUrl;
    }

    public String getRawSpecification() {
        return rawSpecification;
    }

    public void setRawSpecification(String rawSpecification) {
        this.rawSpecification = rawSpecification;
    }

    public int getEndpointsCount() {
        return endpointsCount;
    }

    public void setEndpointsCount(int endpointsCount) {
        this.endpointsCount = endpointsCount;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public String getFormattedCreatedAt() {
        return createdAt != null ? createdAt.format(DATE_FORMATTER) : "—";
    }

    @Override
    public String toString() {
        return "ApiProject{" +
                "id=" + id +
                ", userId=" + userId +
                ", name='" + name + '\'' +
                ", specType=" + specType +
                ", specFormat=" + specFormat +
                ", endpointsCount=" + endpointsCount +
                '}';
    }
}

