package com.webshield.database.entities;

import com.webshield.api.models.SourceType;
import com.webshield.api.models.SpecFormat;
import com.webshield.api.models.SpecType;
import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity representing an API security testing project mapped to table {@code api_projects}.
 */
@Entity
@Table(name = "api_projects")
public class ApiProjectEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "name", nullable = false, length = 150)
    private String name;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(name = "spec_type", nullable = false, length = 20)
    private SpecType specType = SpecType.OPENAPI_3;

    @Enumerated(EnumType.STRING)
    @Column(name = "spec_format", nullable = false, length = 10)
    private SpecFormat specFormat = SpecFormat.JSON;

    @Enumerated(EnumType.STRING)
    @Column(name = "source_type", nullable = false, length = 20)
    private SourceType sourceType = SourceType.FILE_UPLOAD;

    @Column(name = "source_url", length = 2048)
    private String sourceUrl;

    @Lob
    @Column(name = "raw_specification", nullable = false, columnDefinition = "MEDIUMTEXT")
    private String rawSpecification;

    @Column(name = "endpoints_count", nullable = false)
    private int endpointsCount = 0;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt = LocalDateTime.now();

    public ApiProjectEntity() {
    }

    public ApiProjectEntity(Long userId, String name, String description,
                            SpecType specType, SpecFormat specFormat,
                            SourceType sourceType, String sourceUrl,
                            String rawSpecification, int endpointsCount) {
        this.userId = userId;
        this.name = name;
        this.description = description;
        this.specType = specType != null ? specType : SpecType.OPENAPI_3;
        this.specFormat = specFormat != null ? specFormat : SpecFormat.JSON;
        this.sourceType = sourceType != null ? sourceType : SourceType.FILE_UPLOAD;
        this.sourceUrl = sourceUrl;
        this.rawSpecification = rawSpecification;
        this.endpointsCount = endpointsCount;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    public void onUpdate() {
        this.updatedAt = LocalDateTime.now();
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
}

