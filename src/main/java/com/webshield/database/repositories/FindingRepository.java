package com.webshield.database.repositories;

import com.webshield.assessment.models.AssessmentResult;
import com.webshield.assessment.models.ConfidenceLevel;
import com.webshield.assessment.models.Severity;
import com.webshield.config.DatabaseConfig;
import com.webshield.findings.FindingStatus;
import com.webshield.models.FindingEvidence;
import com.webshield.models.SecurityFinding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.*;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for retrieving, persisting, and updating security assessment findings.
 */
@Repository
public class FindingRepository {

    private static final Logger log = LoggerFactory.getLogger(FindingRepository.class);

    private static final String SELECT_FINDINGS_BY_USER = """
            SELECT sf.id, sf.scan_id, sf.vulnerability_id, sf.page_id, sf.severity, sf.status,
                   sf.affected_url, sf.affected_param, sf.http_method, sf.finding_name,
                   sf.description, sf.evidence, sf.detection_method, sf.request_headers,
                   sf.response_excerpt, sf.detected_at,
                   s.website_id, w.name AS website_name,
                   v.code AS vuln_code, v.category AS vuln_category, v.remediation
            FROM scan_findings sf
            JOIN scans s ON sf.scan_id = s.id
            JOIN websites w ON s.website_id = w.id
            LEFT JOIN vulnerabilities v ON sf.vulnerability_id = v.id
            WHERE s.user_id = ?
            ORDER BY sf.detected_at DESC
            """;

    private static final String SELECT_FINDINGS_BY_SCAN = """
            SELECT sf.id, sf.scan_id, sf.vulnerability_id, sf.page_id, sf.severity, sf.status,
                   sf.affected_url, sf.affected_param, sf.http_method, sf.finding_name,
                   sf.description, sf.evidence, sf.detection_method, sf.request_headers,
                   sf.response_excerpt, sf.detected_at,
                   s.website_id, w.name AS website_name,
                   v.code AS vuln_code, v.category AS vuln_category, v.remediation
            FROM scan_findings sf
            JOIN scans s ON sf.scan_id = s.id
            JOIN websites w ON s.website_id = w.id
            LEFT JOIN vulnerabilities v ON sf.vulnerability_id = v.id
            WHERE sf.scan_id = ?
            ORDER BY sf.detected_at DESC
            """;

    private static final String SELECT_FINDING_BY_ID = """
            SELECT sf.id, sf.scan_id, sf.vulnerability_id, sf.page_id, sf.severity, sf.status,
                   sf.affected_url, sf.affected_param, sf.http_method, sf.finding_name,
                   sf.description, sf.evidence, sf.detection_method, sf.request_headers,
                   sf.response_excerpt, sf.detected_at,
                   s.website_id, w.name AS website_name,
                   v.code AS vuln_code, v.category AS vuln_category, v.remediation
            FROM scan_findings sf
            JOIN scans s ON sf.scan_id = s.id
            JOIN websites w ON s.website_id = w.id
            LEFT JOIN vulnerabilities v ON sf.vulnerability_id = v.id
            WHERE sf.id = ? AND s.user_id = ?
            """;

    private static final String INSERT_FINDING = """
            INSERT INTO scan_findings
            (scan_id, vulnerability_id, page_id, severity, status,
             affected_url, affected_param, http_method, finding_name,
             description, evidence, detection_method, request_headers, response_excerpt, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

    private static final String UPDATE_FINDING_STATUS = """
            UPDATE scan_findings
            SET status = ?
            WHERE id = ?
            """;

    /**
     * Retrieves all findings for a given user as {@link SecurityFinding} domain models.
     */
    public List<SecurityFinding> findSecurityFindingsByUserId(int userId) {
        List<SecurityFinding> list = new ArrayList<>();
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(SELECT_FINDINGS_BY_USER)) {

            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(mapSecurityFinding(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Failed to query security findings for user id={}", userId, e);
        }
        return list;
    }

    /**
     * Retrieves all findings for a specific scan run.
     */
    public List<SecurityFinding> findSecurityFindingsByScanId(long scanId) {
        List<SecurityFinding> list = new ArrayList<>();
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(SELECT_FINDINGS_BY_SCAN)) {

            ps.setLong(1, scanId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(mapSecurityFinding(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Failed to query security findings for scan id={}", scanId, e);
        }
        return list;
    }

    /**
     * Retrieves a single finding by ID ensuring user isolation.
     */
    public Optional<SecurityFinding> findSecurityFindingById(long findingId, int userId) {
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(SELECT_FINDING_BY_ID)) {

            ps.setLong(1, findingId);
            ps.setInt(2, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapSecurityFinding(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Failed to find security finding id={} for user={}", findingId, userId, e);
        }
        return Optional.empty();
    }

    /**
     * Updates the status of a finding (e.g. marking as FALSE_POSITIVE, RESOLVED, etc.).
     */
    public boolean updateFindingStatus(long findingId, FindingStatus newStatus) {
        if (newStatus == null) return false;

        // Map FindingStatus to MySQL enum ('CONFIRMED','POTENTIAL','FALSE_POSITIVE','INFORMATIONAL')
        String dbStatus = switch (newStatus) {
            case FALSE_POSITIVE -> "FALSE_POSITIVE";
            case RESOLVED -> "CONFIRMED"; // Or mark resolved with confirmation
            case UNDER_REVIEW -> "POTENTIAL";
            case OPEN -> "CONFIRMED";
        };

        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(UPDATE_FINDING_STATUS)) {

            ps.setString(1, dbStatus);
            ps.setLong(2, findingId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            log.error("Failed to update status for finding id={}", findingId, e);
            return false;
        }
    }

    /**
     * Inserts a single finding into MySQL.
     */
    public long insertFinding(SecurityFinding f) {
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(INSERT_FINDING, Statement.RETURN_GENERATED_KEYS)) {

            bindFindingParams(ps, f);
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                if (rs.next()) {
                    long id = rs.getLong(1);
                    f.setId(id);
                    return id;
                }
            }
        } catch (SQLException e) {
            log.error("Failed to insert security finding", e);
        }
        return 0;
    }

    /**
     * Batch inserts multiple findings under a single transaction.
     */
    public void insertFindingsBatch(long scanId, List<SecurityFinding> findings) {
        if (findings == null || findings.isEmpty()) return;

        try (Connection conn = DatabaseConfig.getInstance().getConnection()) {
            boolean autoCommit = conn.getAutoCommit();
            conn.setAutoCommit(false);
            try (PreparedStatement ps = conn.prepareStatement(INSERT_FINDING, Statement.RETURN_GENERATED_KEYS)) {
                for (SecurityFinding f : findings) {
                    f.setScanId(scanId);
                    bindFindingParams(ps, f);
                    ps.addBatch();
                }
                ps.executeBatch();
                conn.commit();
                log.info("Persisted {} findings in batch for scan id={}", findings.size(), scanId);
            } catch (SQLException e) {
                conn.rollback();
                log.error("Transaction rolled back while inserting findings batch for scan id={}", scanId, e);
                throw e;
            } finally {
                conn.setAutoCommit(autoCommit);
            }
        } catch (SQLException e) {
            log.error("Failed to batch insert findings for scan id={}", scanId, e);
        }
    }

    /**
     * Counts findings grouped by severity for a user.
     */
    public Map<Severity, Long> countFindingsBySeverity(int userId) {
        String sql = """
                SELECT sf.severity, COUNT(*) AS cnt
                FROM scan_findings sf
                JOIN scans s ON sf.scan_id = s.id
                WHERE s.user_id = ?
                GROUP BY sf.severity
                """;
        Map<Severity, Long> map = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) map.put(s, 0L);

        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    try {
                        Severity sev = Severity.valueOf(rs.getString("severity"));
                        map.put(sev, rs.getLong("cnt"));
                    } catch (Exception ignored) {}
                }
            }
        } catch (SQLException e) {
            log.error("Failed to count findings by severity for user id={}", userId, e);
        }
        return map;
    }

    /**
     * Counts findings grouped by severity for a specific scan.
     */
    public Map<Severity, Long> countFindingsBySeverityForScan(long scanId) {
        String sql = """
                SELECT severity, COUNT(*) AS cnt
                FROM scan_findings
                WHERE scan_id = ?
                GROUP BY severity
                """;
        Map<Severity, Long> map = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) map.put(s, 0L);

        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setLong(1, scanId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    try {
                        Severity sev = Severity.valueOf(rs.getString("severity"));
                        map.put(sev, rs.getLong("cnt"));
                    } catch (Exception ignored) {}
                }
            }
        } catch (SQLException e) {
            log.error("Failed to count findings by severity for scan id={}", scanId, e);
        }
        return map;
    }

    // --- Backwards Compatibility for existing AssessmentResult consumers ---

    public List<AssessmentResult> findAllByUserId(int userId) {
        List<SecurityFinding> sfList = findSecurityFindingsByUserId(userId);
        List<AssessmentResult> arList = new ArrayList<>();
        for (SecurityFinding sf : sfList) {
            arList.add(sf.toAssessmentResult());
        }
        return arList;
    }

    public List<AssessmentResult> findAllByScanId(long scanId) {
        List<SecurityFinding> sfList = findSecurityFindingsByScanId(scanId);
        List<AssessmentResult> arList = new ArrayList<>();
        for (SecurityFinding sf : sfList) {
            arList.add(sf.toAssessmentResult());
        }
        return arList;
    }

    // --- Private helpers ---

    private void bindFindingParams(PreparedStatement ps, SecurityFinding f) throws SQLException {
        ps.setLong(1, f.getScanId());
        if (f.getVulnerabilityId() != null && f.getVulnerabilityId() > 0) {
            ps.setInt(2, f.getVulnerabilityId());
        } else {
            ps.setNull(2, Types.INTEGER);
        }
        ps.setNull(3, Types.BIGINT); // page_id

        ps.setString(4, f.getSeverity() != null ? f.getSeverity().name() : Severity.INFORMATIONAL.name());
        ps.setString(5, f.getConfidenceLevel() != null ? f.getConfidenceLevel().name() : ConfidenceLevel.POTENTIAL.name());
        ps.setString(6, f.getAffectedUrl());
        ps.setString(7, f.getAffectedParam());
        ps.setString(8, f.getHttpMethod() != null ? f.getHttpMethod() : "GET");
        ps.setString(9, f.getFindingName());
        ps.setString(10, f.getDescription());
        ps.setString(11, f.getEvidence() != null ? f.getEvidence().getFormattedSummary() : null);
        ps.setString(12, f.getDetectionMethod());
        ps.setString(13, f.getEvidence() != null ? f.getEvidence().getRequestHeaders() : null);
        ps.setString(14, f.getEvidence() != null ? f.getEvidence().getResponseExcerpt() : null);

        LocalDateTime det = f.getDetectedAt() != null ? f.getDetectedAt() : LocalDateTime.now();
        ps.setTimestamp(15, Timestamp.valueOf(det));
    }

    private SecurityFinding mapSecurityFinding(ResultSet rs) throws SQLException {
        SecurityFinding sf = new SecurityFinding();
        sf.setId(rs.getLong("id"));
        sf.setScanId(rs.getLong("scan_id"));
        sf.setWebsiteId(rs.getLong("website_id"));
        sf.setWebsiteName(rs.getString("website_name"));

        int vulnId = rs.getInt("vulnerability_id");
        if (!rs.wasNull()) sf.setVulnerabilityId(vulnId);

        sf.setVulnerabilityCode(rs.getString("vuln_code"));
        sf.setFindingName(rs.getString("finding_name"));
        sf.setCategory(rs.getString("vuln_category") != null ? rs.getString("vuln_category") : "Web Vulnerability");
        sf.setAffectedUrl(rs.getString("affected_url"));
        sf.setAffectedParam(rs.getString("affected_param"));
        sf.setHttpMethod(rs.getString("http_method"));

        Severity sev = Severity.INFORMATIONAL;
        try {
            sev = Severity.valueOf(rs.getString("severity"));
        } catch (Exception ignored) {}
        sf.setSeverity(sev);

        ConfidenceLevel conf = ConfidenceLevel.POTENTIAL;
        try {
            conf = ConfidenceLevel.valueOf(rs.getString("status"));
        } catch (Exception ignored) {}
        sf.setConfidenceLevel(conf);

        if (conf == ConfidenceLevel.FALSE_POSITIVE) {
            sf.setFindingStatus(FindingStatus.FALSE_POSITIVE);
        } else {
            sf.setFindingStatus(FindingStatus.OPEN);
        }

        FindingEvidence ev = new FindingEvidence();
        ev.setDescription(rs.getString("evidence"));
        ev.setRequestHeaders(rs.getString("request_headers"));
        ev.setResponseExcerpt(rs.getString("response_excerpt"));
        sf.setEvidence(ev);

        sf.setDescription(rs.getString("description"));
        sf.setRemediation(rs.getString("remediation"));
        sf.setDetectionMethod(rs.getString("detection_method"));

        Timestamp ts = rs.getTimestamp("detected_at");
        if (ts != null) sf.setDetectedAt(ts.toLocalDateTime());

        return sf;
    }
}
