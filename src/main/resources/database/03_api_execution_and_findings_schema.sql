-- =============================================================================
-- WebShield Part 2 Database Schema Extension: Module H Persistence Layer
-- MySQL 8.0 | UTF-8 mb4 | InnoDB
-- Non-destructive extension for API execution, test cases, findings, and scan history
-- =============================================================================

SET NAMES utf8mb4;
SET time_zone = '+00:00';

USE webshield;

-- =============================================================================
-- TABLE: api_scans
-- Stores historical records and lifecycle states of API security testing scans.
-- =============================================================================
CREATE TABLE IF NOT EXISTS api_scans (
    id                          BIGINT       UNSIGNED NOT NULL AUTO_INCREMENT,
    api_project_id              BIGINT       UNSIGNED NOT NULL,
    user_id                     BIGINT       UNSIGNED NOT NULL,
    scan_name                   VARCHAR(150) NOT NULL,
    status                      VARCHAR(32)  NOT NULL DEFAULT 'PENDING',
    started_at                  DATETIME,
    completed_at                DATETIME,
    duration_ms                 BIGINT       UNSIGNED NOT NULL DEFAULT 0,
    total_endpoints             INT          UNSIGNED NOT NULL DEFAULT 0,
    total_generated_test_cases  INT          UNSIGNED NOT NULL DEFAULT 0,
    total_executed_requests     INT          UNSIGNED NOT NULL DEFAULT 0,
    total_findings              INT          UNSIGNED NOT NULL DEFAULT 0,
    critical_count              INT          UNSIGNED NOT NULL DEFAULT 0,
    high_count                  INT          UNSIGNED NOT NULL DEFAULT 0,
    medium_count                INT          UNSIGNED NOT NULL DEFAULT 0,
    low_count                   INT          UNSIGNED NOT NULL DEFAULT 0,
    informational_count         INT          UNSIGNED NOT NULL DEFAULT 0,
    search_config_snapshot      TEXT,
    execution_config_snapshot   TEXT,
    termination_reason          VARCHAR(64),
    error_message               TEXT,
    created_at                  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_api_scans_project
        FOREIGN KEY (api_project_id) REFERENCES api_projects(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_api_scans_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_api_scans_project (api_project_id),
    INDEX idx_api_scans_user (user_id),
    INDEX idx_api_scans_status (status),
    INDEX idx_api_scans_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Historical records and lifecycle states of API security test scans';


-- =============================================================================
-- TABLE: api_executions
-- Stores individual HTTP request execution observations dispatched during an API scan.
-- Response bodies are subject to size bounds and sensitive data redaction.
-- =============================================================================
CREATE TABLE IF NOT EXISTS api_executions (
    id                  BIGINT       UNSIGNED NOT NULL AUTO_INCREMENT,
    execution_uuid      VARCHAR(64)  NOT NULL,
    scan_id             BIGINT       UNSIGNED NOT NULL,
    test_case_id        VARCHAR(64)  NOT NULL,
    endpoint            VARCHAR(1024)NOT NULL,
    http_method         VARCHAR(16)  NOT NULL,
    outcome             VARCHAR(32)  NOT NULL,
    status_code         INT          NOT NULL DEFAULT 0,
    response_time_ms    BIGINT       NOT NULL DEFAULT 0,
    response_size_bytes BIGINT       NOT NULL DEFAULT 0,
    response_headers    TEXT,
    response_body       MEDIUMTEXT,
    is_body_truncated   TINYINT(1)   NOT NULL DEFAULT 0,
    is_binary_response  TINYINT(1)   NOT NULL DEFAULT 0,
    error_message       TEXT,
    executed_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_api_executions_scan
        FOREIGN KEY (scan_id) REFERENCES api_scans(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_api_exec_scan (scan_id),
    INDEX idx_api_exec_uuid (execution_uuid),
    INDEX idx_api_exec_test_case (test_case_id),
    INDEX idx_api_exec_outcome (outcome),
    INDEX idx_api_exec_endpoint (endpoint(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Individual HTTP dispatch outcomes and sanitized response captures';


-- =============================================================================
-- TABLE: api_findings
-- Stores security weaknesses and misconfigurations discovered by Module G analysis.
-- Findings are historically separated across distinct scans.
-- =============================================================================
CREATE TABLE IF NOT EXISTS api_findings (
    id                  BIGINT       UNSIGNED NOT NULL AUTO_INCREMENT,
    finding_uuid        VARCHAR(64)  NOT NULL,
    scan_id             BIGINT       UNSIGNED NOT NULL,
    api_project_id      BIGINT       UNSIGNED NOT NULL,
    execution_uuid      VARCHAR(64),
    rule_id             VARCHAR(64)  NOT NULL,
    title               VARCHAR(255) NOT NULL,
    description         TEXT,
    severity            VARCHAR(32)  NOT NULL,
    confidence          VARCHAR(32)  NOT NULL,
    http_method         VARCHAR(16)  NOT NULL,
    endpoint_path       VARCHAR(1024)NOT NULL,
    parameter_or_field  VARCHAR(255),
    evidence            TEXT,
    cwe_id              VARCHAR(32)  NOT NULL,
    owasp_category      VARCHAR(64)  NOT NULL,
    remediation         TEXT,
    is_confirmed        TINYINT(1)   NOT NULL DEFAULT 0,
    lifecycle_status    VARCHAR(32)  NOT NULL DEFAULT 'ACTIVE',
    detected_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_api_findings_scan
        FOREIGN KEY (scan_id) REFERENCES api_scans(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_api_findings_project
        FOREIGN KEY (api_project_id) REFERENCES api_projects(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_api_findings_scan (scan_id),
    INDEX idx_api_findings_project (api_project_id),
    INDEX idx_api_findings_rule (rule_id),
    INDEX idx_api_findings_severity (severity),
    INDEX idx_api_findings_endpoint (endpoint_path(255)),
    INDEX idx_api_findings_uuid (finding_uuid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Discovered API security findings with OWASP and CWE classifications';


-- =============================================================================
-- TABLE: api_test_case_results
-- Preserves generated test case definitions, categories, and mutation lineages.
-- =============================================================================
CREATE TABLE IF NOT EXISTS api_test_case_results (
    id                  BIGINT       UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id             BIGINT       UNSIGNED NOT NULL,
    test_case_id        VARCHAR(64)  NOT NULL,
    endpoint_identifier VARCHAR(255) NOT NULL,
    http_method         VARCHAR(16)  NOT NULL,
    category            VARCHAR(32)  NOT NULL,
    strategy            VARCHAR(64)  NOT NULL,
    parent_test_case_id VARCHAR(64),
    targeted_property   VARCHAR(255),
    targeted_constraint VARCHAR(255),
    description         VARCHAR(512),
    created_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_api_tc_scan
        FOREIGN KEY (scan_id) REFERENCES api_scans(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_api_tc_scan (scan_id),
    INDEX idx_api_tc_id (test_case_id),
    INDEX idx_api_tc_category (category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Generated API test case attributes and mutation lineage tracking';


-- =============================================================================
-- TABLE: api_scan_statistics
-- Stores aggregate performance and coverage metrics for a completed API scan.
-- =============================================================================
CREATE TABLE IF NOT EXISTS api_scan_statistics (
    id                          BIGINT       UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id                     BIGINT       UNSIGNED NOT NULL,
    avg_response_time_ms        DOUBLE       NOT NULL DEFAULT 0.0,
    min_response_time_ms        BIGINT       NOT NULL DEFAULT 0,
    max_response_time_ms        BIGINT       NOT NULL DEFAULT 0,
    total_data_transferred_bytes BIGINT      NOT NULL DEFAULT 0,
    status_2xx_count            INT          NOT NULL DEFAULT 0,
    status_4xx_count            INT          NOT NULL DEFAULT 0,
    status_5xx_count            INT          NOT NULL DEFAULT 0,
    error_outcomes_count        INT          NOT NULL DEFAULT 0,
    objectives_achieved         INT          NOT NULL DEFAULT 0,
    total_objectives            INT          NOT NULL DEFAULT 0,
    coverage_percentage         DOUBLE       NOT NULL DEFAULT 0.0,
    calculated_at               DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_api_stats_scan
        FOREIGN KEY (scan_id) REFERENCES api_scans(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    UNIQUE KEY uq_api_scan_stats_scan (scan_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Aggregate performance and objective coverage statistics for an API scan';

