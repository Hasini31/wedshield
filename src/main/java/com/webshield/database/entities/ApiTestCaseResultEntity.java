package com.webshield.database.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity representing generated API test case metadata and lineage mapped to table {@code api_test_case_results}.
 */
@Entity
@Table(name = "api_test_case_results")
public class ApiTestCaseResultEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "scan_id", nullable = false)
    private Long scanId;

    @Column(name = "test_case_id", nullable = false, length = 64)
    private String testCaseId;

    @Column(name = "endpoint_identifier", nullable = false, length = 255)
    private String endpointIdentifier;

    @Column(name = "http_method", nullable = false, length = 16)
    private String httpMethod;

    @Column(name = "category", nullable = false, length = 32)
    private String category;

    @Column(name = "strategy", nullable = false, length = 64)
    private String strategy;

    @Column(name = "parent_test_case_id", length = 64)
    private String parentTestCaseId;

    @Column(name = "targeted_property", length = 255)
    private String targetedProperty;

    @Column(name = "targeted_constraint", length = 255)
    private String targetedConstraint;

    @Column(name = "description", length = 512)
    private String description;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    public ApiTestCaseResultEntity() {
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getScanId() { return scanId; }
    public void setScanId(Long scanId) { this.scanId = scanId; }

    public String getTestCaseId() { return testCaseId; }
    public void setTestCaseId(String testCaseId) { this.testCaseId = testCaseId; }

    public String getEndpointIdentifier() { return endpointIdentifier; }
    public void setEndpointIdentifier(String endpointIdentifier) { this.endpointIdentifier = endpointIdentifier; }

    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }

    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }

    public String getStrategy() { return strategy; }
    public void setStrategy(String strategy) { this.strategy = strategy; }

    public String getParentTestCaseId() { return parentTestCaseId; }
    public void setParentTestCaseId(String parentTestCaseId) { this.parentTestCaseId = parentTestCaseId; }

    public String getTargetedProperty() { return targetedProperty; }
    public void setTargetedProperty(String targetedProperty) { this.targetedProperty = targetedProperty; }

    public String getTargetedConstraint() { return targetedConstraint; }
    public void setTargetedConstraint(String targetedConstraint) { this.targetedConstraint = targetedConstraint; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}

