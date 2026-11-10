-- =============================================================================
-- WebShield Part 2 Database Schema Extension: Module J Reporting Layer
-- MySQL 8.0 | UTF-8 mb4 | InnoDB
-- Non-destructive extension for API security test report metadata tracking
-- =============================================================================

SET NAMES utf8mb4;
SET time_zone = '+00:00';

USE webshield;

-- =============================================================================
-- TABLE: api_reports
-- Stores metadata of generated PDF and HTML reports for API security scans.
-- Does not duplicate sensitive request/response payloads.
-- =============================================================================
CREATE TABLE IF NOT EXISTS api_reports (
    id                  BIGINT       UNSIGNED NOT NULL AUTO_INCREMENT,
    api_scan_id         BIGINT       UNSIGNED NOT NULL,
    user_id             BIGINT       UNSIGNED NOT NULL,
    report_name         VARCHAR(150) NOT NULL,
    report_format       VARCHAR(16)  NOT NULL,
    file_path           VARCHAR(512) NOT NULL,
    file_size_bytes     BIGINT       UNSIGNED NOT NULL DEFAULT 0,
    has_ai_explanations BOOLEAN      NOT NULL DEFAULT FALSE,
    status              VARCHAR(32)  NOT NULL DEFAULT 'COMPLETED',
    created_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_api_reports_scan
        FOREIGN KEY (api_scan_id) REFERENCES api_scans(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_api_reports_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_api_reports_user (user_id),
    INDEX idx_api_reports_scan (api_scan_id),
    INDEX idx_api_reports_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Metadata records for generated PDF and HTML API security assessment reports';

