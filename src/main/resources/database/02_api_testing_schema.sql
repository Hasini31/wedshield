-- =============================================================================
-- WebShield Part 2 Database Schema Extension: API Security Testing
-- MySQL 8.0 | UTF-8 mb4 | InnoDB
-- Non-destructive extension for Module A: API Project Management
-- =============================================================================

SET NAMES utf8mb4;
SET time_zone = '+00:00';

USE webshield;

-- =============================================================================
-- TABLE: api_projects
-- Stores API security testing projects and imported OpenAPI/Swagger specifications.
-- =============================================================================
CREATE TABLE IF NOT EXISTS api_projects (
    id                  BIGINT       UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id             BIGINT       UNSIGNED NOT NULL,
    name                VARCHAR(150) NOT NULL,
    description         TEXT,
    spec_type           ENUM('OPENAPI_3', 'SWAGGER_2', 'UNKNOWN') NOT NULL DEFAULT 'OPENAPI_3',
    spec_format         ENUM('JSON', 'YAML') NOT NULL DEFAULT 'JSON',
    source_type         ENUM('FILE_UPLOAD', 'URL') NOT NULL DEFAULT 'FILE_UPLOAD',
    source_url          VARCHAR(2048),
    raw_specification   MEDIUMTEXT   NOT NULL,
    endpoints_count     INT UNSIGNED NOT NULL DEFAULT 0,
    created_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_api_projects_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_api_projects_user (user_id),
    INDEX idx_api_projects_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='API security testing projects and imported OpenAPI/Swagger specifications';

