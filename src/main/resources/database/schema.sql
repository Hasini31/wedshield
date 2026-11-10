-- =============================================================================
-- WebShield Database Schema
-- MySQL 8.0 | UTF-8 mb4 | InnoDB
-- Auto-executed by Docker on first container start
-- =============================================================================

SET NAMES utf8mb4;
SET time_zone = '+00:00';

-- Use the database created by docker-compose environment variables
USE webshield;

-- =============================================================================
-- TABLE: users
-- Stores registered operator accounts.
-- Passwords are stored as BCrypt hashes ONLY — never plaintext.
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
    id            BIGINT       UNSIGNED NOT NULL AUTO_INCREMENT,
    full_name     VARCHAR(120) NOT NULL,
    email         VARCHAR(255) NOT NULL,
    password_hash VARCHAR(72)  NOT NULL           COMMENT 'BCrypt hash (60-char output, stored with headroom)',
    is_active     TINYINT(1)   NOT NULL DEFAULT 1,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE  KEY uq_users_email (email),
    INDEX   idx_users_active  (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='WebShield operator accounts';


-- =============================================================================
-- TABLE: websites
-- Stores authorized target websites registered by users.
-- Crawling and scanning is restricted to these entries.
-- =============================================================================
CREATE TABLE IF NOT EXISTS websites (
    id                  BIGINT       UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id             BIGINT       UNSIGNED NOT NULL,
    name                VARCHAR(120) NOT NULL,
    url                 VARCHAR(2048)NOT NULL,
    description         TEXT,
    is_authorized       TINYINT(1)   NOT NULL DEFAULT 0  COMMENT '1 when user confirmed authorization',
    status              ENUM('ACTIVE','INACTIVE','ARCHIVED') NOT NULL DEFAULT 'ACTIVE',
    last_scan_at        DATETIME,
    created_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_websites_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_websites_user   (user_id),
    INDEX idx_websites_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Authorized target websites registered per user';


-- =============================================================================
-- TABLE: scans
-- Represents one full security assessment run against a website.
-- =============================================================================
CREATE TABLE IF NOT EXISTS scans (
    id               BIGINT   UNSIGNED NOT NULL AUTO_INCREMENT,
    website_id       BIGINT   UNSIGNED NOT NULL,
    user_id          BIGINT   UNSIGNED NOT NULL,
    status           ENUM('QUEUED','CRAWLING','SCANNING','COMPLETED','FAILED','CANCELLED')
                              NOT NULL DEFAULT 'QUEUED',
    crawl_depth      TINYINT  UNSIGNED NOT NULL DEFAULT 3,
    max_pages        SMALLINT UNSIGNED NOT NULL DEFAULT 100,
    timeout_seconds  SMALLINT UNSIGNED NOT NULL DEFAULT 15,

    -- Which assessment categories were enabled
    check_headers         TINYINT(1) NOT NULL DEFAULT 1,
    check_cookies         TINYINT(1) NOT NULL DEFAULT 1,
    check_reflection      TINYINT(1) NOT NULL DEFAULT 1,
    check_sql_errors      TINYINT(1) NOT NULL DEFAULT 1,
    check_input_validation TINYINT(1) NOT NULL DEFAULT 1,

    pages_discovered  INT      UNSIGNED NOT NULL DEFAULT 0,
    pages_tested      INT      UNSIGNED NOT NULL DEFAULT 0,
    findings_count    INT      UNSIGNED NOT NULL DEFAULT 0,

    started_at        DATETIME,
    completed_at      DATETIME,
    error_message     TEXT,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_scans_website
        FOREIGN KEY (website_id) REFERENCES websites(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_scans_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX idx_scans_website (website_id),
    INDEX idx_scans_user    (user_id),
    INDEX idx_scans_status  (status),
    INDEX idx_scans_started (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Security assessment runs';


-- =============================================================================
-- TABLE: discovered_pages
-- Every URL the crawler discovers during a scan.
-- =============================================================================
CREATE TABLE IF NOT EXISTS discovered_pages (
    id              BIGINT        UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id         BIGINT        UNSIGNED NOT NULL,
    website_id      BIGINT        UNSIGNED NOT NULL,
    url             VARCHAR(2048) NOT NULL,
    page_title      VARCHAR(512),
    http_method     VARCHAR(10)   NOT NULL DEFAULT 'GET',
    status_code     SMALLINT,
    content_type    VARCHAR(128),
    depth           TINYINT UNSIGNED NOT NULL DEFAULT 0,
    has_forms       TINYINT(1)    NOT NULL DEFAULT 0,
    was_tested      TINYINT(1)    NOT NULL DEFAULT 0,
    discovered_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_pages_scan
        FOREIGN KEY (scan_id)    REFERENCES scans(id)    ON DELETE CASCADE,
    CONSTRAINT fk_pages_website
        FOREIGN KEY (website_id) REFERENCES websites(id) ON DELETE CASCADE,
    INDEX idx_pages_scan    (scan_id),
    INDEX idx_pages_website (website_id),
    INDEX idx_pages_depth   (depth)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='URLs discovered during a crawl';


-- =============================================================================
-- TABLE: forms
-- HTML forms discovered on discovered pages.
-- =============================================================================
CREATE TABLE IF NOT EXISTS forms (
    id           BIGINT        UNSIGNED NOT NULL AUTO_INCREMENT,
    page_id      BIGINT        UNSIGNED NOT NULL,
    scan_id      BIGINT        UNSIGNED NOT NULL,
    form_action  VARCHAR(2048),
    form_method  VARCHAR(10)   NOT NULL DEFAULT 'GET',
    form_id      VARCHAR(256)           COMMENT 'HTML id attribute',
    form_name    VARCHAR(256)           COMMENT 'HTML name attribute',
    field_count  TINYINT UNSIGNED NOT NULL DEFAULT 0,
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_forms_page
        FOREIGN KEY (page_id)  REFERENCES discovered_pages(id) ON DELETE CASCADE,
    CONSTRAINT fk_forms_scan
        FOREIGN KEY (scan_id)  REFERENCES scans(id)            ON DELETE CASCADE,
    INDEX idx_forms_page (page_id),
    INDEX idx_forms_scan (scan_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='HTML forms discovered during crawling';


-- =============================================================================
-- TABLE: input_fields
-- Individual input elements belonging to a discovered form.
-- =============================================================================
CREATE TABLE IF NOT EXISTS input_fields (
    id              BIGINT       UNSIGNED NOT NULL AUTO_INCREMENT,
    form_id         BIGINT       UNSIGNED NOT NULL,
    field_name      VARCHAR(256),
    field_type      VARCHAR(64)  NOT NULL DEFAULT 'text',
    field_id        VARCHAR(256),
    placeholder     VARCHAR(512),
    is_required     TINYINT(1)   NOT NULL DEFAULT 0,
    has_maxlength   TINYINT(1)   NOT NULL DEFAULT 0,
    has_pattern     TINYINT(1)   NOT NULL DEFAULT 0,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_fields_form
        FOREIGN KEY (form_id) REFERENCES forms(id) ON DELETE CASCADE,
    INDEX idx_fields_form (form_id),
    INDEX idx_fields_type (field_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Input fields within discovered forms';


-- =============================================================================
-- TABLE: vulnerabilities
-- The catalogue of known vulnerability types WebShield can detect.
-- Populated once; referenced by scan_findings.
-- =============================================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id               INT          UNSIGNED NOT NULL AUTO_INCREMENT,
    code             VARCHAR(64)  NOT NULL           COMMENT 'Internal code e.g. WS-HDR-001',
    name             VARCHAR(255) NOT NULL,
    category         VARCHAR(128) NOT NULL,
    default_severity ENUM('CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL') NOT NULL,
    description      TEXT         NOT NULL,
    impact           TEXT,
    remediation      TEXT,
    reference        VARCHAR(512)           COMMENT 'CWE / OWASP reference URL',

    PRIMARY KEY (id),
    UNIQUE KEY uq_vuln_code (code),
    INDEX idx_vuln_category (category),
    INDEX idx_vuln_severity (default_severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Catalogue of detectable vulnerability types';


-- =============================================================================
-- TABLE: scan_findings
-- Individual findings produced by a scan against a specific URL/parameter.
-- =============================================================================
CREATE TABLE IF NOT EXISTS scan_findings (
    id               BIGINT       UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id          BIGINT       UNSIGNED NOT NULL,
    vulnerability_id INT          UNSIGNED,
    page_id          BIGINT       UNSIGNED,

    -- Finding classification
    severity         ENUM('CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL') NOT NULL,
    status           ENUM('CONFIRMED','POTENTIAL','FALSE_POSITIVE','INFORMATIONAL') NOT NULL DEFAULT 'POTENTIAL',

    -- Target details
    affected_url     VARCHAR(2048) NOT NULL,
    affected_param   VARCHAR(512),
    http_method      VARCHAR(10)   NOT NULL DEFAULT 'GET',

    -- Evidence
    finding_name     VARCHAR(255)  NOT NULL,
    description      TEXT,
    evidence         TEXT                    COMMENT 'Response excerpt or indicator',
    detection_method VARCHAR(255),
    request_headers  TEXT,
    response_excerpt TEXT,

    detected_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    CONSTRAINT fk_findings_scan
        FOREIGN KEY (scan_id)          REFERENCES scans(id)           ON DELETE CASCADE,
    CONSTRAINT fk_findings_vuln
        FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    CONSTRAINT fk_findings_page
        FOREIGN KEY (page_id)          REFERENCES discovered_pages(id) ON DELETE SET NULL,
    INDEX idx_findings_scan     (scan_id),
    INDEX idx_findings_severity (severity),
    INDEX idx_findings_status   (status),
    INDEX idx_findings_detected (detected_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Security findings from assessment scans';


-- =============================================================================
-- SEED: vulnerabilities catalogue
-- Pre-populate the known vulnerability types that WebShield can detect.
-- =============================================================================
INSERT IGNORE INTO vulnerabilities (code, name, category, default_severity, description, impact, remediation, reference) VALUES

('WS-HDR-001', 'Missing Content-Security-Policy',
 'Security Headers', 'HIGH',
 'The Content-Security-Policy (CSP) header is absent from the HTTP response. CSP controls which resources the browser is permitted to load.',
 'Increases the risk of XSS attacks by allowing arbitrary script execution.',
 'Define a strict CSP header: Content-Security-Policy: default-src ''self''; script-src ''self''; ...',
 'https://owasp.org/www-project-secure-headers/'),

('WS-HDR-002', 'Missing Strict-Transport-Security',
 'Security Headers', 'HIGH',
 'The HTTP Strict-Transport-Security (HSTS) header is missing. HSTS instructs browsers to use HTTPS only.',
 'Users may connect over insecure HTTP, exposing traffic to man-in-the-middle attacks.',
 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
 'https://owasp.org/www-project-secure-headers/'),

('WS-HDR-003', 'Missing X-Frame-Options',
 'Security Headers', 'MEDIUM',
 'The X-Frame-Options header is absent. Without it the page can be embedded in an iframe on another origin.',
 'Enables clickjacking attacks.',
 'Add: X-Frame-Options: DENY  or use CSP frame-ancestors ''none''',
 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'),

('WS-HDR-004', 'Missing X-Content-Type-Options',
 'Security Headers', 'LOW',
 'The X-Content-Type-Options header is not set to nosniff.',
 'Browser may MIME-sniff responses, leading to content injection.',
 'Add: X-Content-Type-Options: nosniff',
 'https://owasp.org/www-project-secure-headers/'),

('WS-HDR-005', 'Missing Referrer-Policy',
 'Security Headers', 'LOW',
 'No Referrer-Policy header is present.',
 'Sensitive URL data may leak in Referer headers to third parties.',
 'Add: Referrer-Policy: strict-origin-when-cross-origin',
 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'),

('WS-CKY-001', 'Cookie Missing HttpOnly Flag',
 'Cookie Security', 'MEDIUM',
 'One or more cookies are set without the HttpOnly attribute, making them accessible to JavaScript.',
 'Session cookies exposed to XSS attacks can be stolen.',
 'Set HttpOnly flag on all session and authentication cookies.',
 'https://owasp.org/www-community/HttpOnly'),

('WS-CKY-002', 'Cookie Missing Secure Flag',
 'Cookie Security', 'MEDIUM',
 'One or more cookies lack the Secure attribute, allowing transmission over unencrypted HTTP.',
 'Cookie may be intercepted over HTTP connections.',
 'Set the Secure attribute on all cookies.',
 'https://owasp.org/www-community/controls/SecureCookieAttribute'),

('WS-CKY-003', 'Cookie Missing SameSite Attribute',
 'Cookie Security', 'LOW',
 'Cookies are set without a SameSite attribute.',
 'Increases CSRF risk as cookies are sent with cross-site requests.',
 'Set SameSite=Strict or SameSite=Lax on all cookies.',
 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite'),

('WS-REF-001', 'Potential Input Reflection',
 'Input Handling', 'HIGH',
 'User-supplied input was reflected back in the HTTP response without apparent encoding. This is an indicator of potential reflected XSS.',
 'Unescaped reflection in HTML context enables reflected cross-site scripting.',
 'Encode all user output using context-appropriate escaping (HTML, attribute, JS, URL).',
 'https://owasp.org/www-community/attacks/xss/'),

('WS-SQL-001', 'SQL Error Message Disclosure',
 'Injection', 'HIGH',
 'Database error messages were detected in the HTTP response. This may indicate that SQL error output is not suppressed.',
 'Reveals database type, schema structure, and may indicate SQL injection vulnerability.',
 'Suppress all database error messages from HTTP responses. Use generic error pages.',
 'https://owasp.org/www-community/attacks/SQL_Injection'),

('WS-INP-001', 'Missing Server-Side Input Validation Indicators',
 'Input Validation', 'INFORMATIONAL',
 'Form fields rely only on client-side validation constraints (required, maxlength, pattern) with no server-side validation evidence.',
 'Client-side validation can be bypassed. Server-side validation is mandatory.',
 'Implement server-side validation for all user inputs.',
 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html');

