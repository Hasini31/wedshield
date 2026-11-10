package com.webshield.database.repositories;

import com.webshield.config.DatabaseConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/**
 * JDBC persistence repository for {@link ScanRecord} entities.
 */
@Repository
public class ScanRepository {

    private static final Logger log = LoggerFactory.getLogger(ScanRepository.class);

    private static final String SELECT_BY_USER = """
            SELECT s.id, s.website_id, s.user_id, s.status, s.crawl_depth, s.max_pages,
                   s.timeout_seconds, s.pages_discovered, s.pages_tested, s.findings_count,
                   s.started_at, s.completed_at, s.created_at, w.name AS website_name
            FROM scans s
            JOIN websites w ON s.website_id = w.id
            WHERE s.user_id = ?
            ORDER BY s.created_at DESC
            """;

    private static final String SELECT_BY_ID = """
            SELECT s.id, s.website_id, s.user_id, s.status, s.crawl_depth, s.max_pages,
                   s.timeout_seconds, s.pages_discovered, s.pages_tested, s.findings_count,
                   s.started_at, s.completed_at, s.created_at, w.name AS website_name
            FROM scans s
            JOIN websites w ON s.website_id = w.id
            WHERE s.id = ? AND s.user_id = ?
            """;

    private static final String UPDATE_STATUS = """
            UPDATE scans
            SET status = ?
            WHERE id = ?
            """;

    private static final String UPDATE_PROGRESS = """
            UPDATE scans
            SET pages_discovered = ?, pages_tested = ?, findings_count = ?
            WHERE id = ?
            """;

    private static final String COMPLETE_SCAN = """
            UPDATE scans
            SET status = ?, pages_discovered = ?, pages_tested = ?, findings_count = ?,
                completed_at = ?, error_message = ?
            WHERE id = ?
            """;

    public List<ScanRecord> findAllByUserId(int userId) {
        List<ScanRecord> scans = new ArrayList<>();
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(SELECT_BY_USER)) {

            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    scans.add(mapRow(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Failed to query scans for user id={}", userId, e);
        }
        return scans;
    }

    public Optional<ScanRecord> findById(long scanId, int userId) {
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(SELECT_BY_ID)) {

            ps.setLong(1, scanId);
            ps.setInt(2, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapRow(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Failed to find scan id={} for user id={}", scanId, userId, e);
        }
        return Optional.empty();
    }

    public long createScan(long websiteId, int userId, int depth, int maxPages, int timeout,
                           boolean headers, boolean cookies, boolean reflection, boolean checkSql, boolean inputVal) {
        String insertSql = """
                INSERT INTO scans
                (website_id, user_id, status, crawl_depth, max_pages, timeout_seconds,
                 check_headers, check_cookies, check_reflection, check_sql_errors, check_input_validation,
                 started_at, created_at)
                VALUES (?, ?, 'QUEUED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;
        LocalDateTime now = LocalDateTime.now();
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {

            ps.setLong(1, websiteId);
            ps.setInt(2, userId);
            ps.setInt(3, depth);
            ps.setInt(4, maxPages);
            ps.setInt(5, timeout);
            ps.setBoolean(6, headers);
            ps.setBoolean(7, cookies);
            ps.setBoolean(8, reflection);
            ps.setBoolean(9, checkSql);
            ps.setBoolean(10, inputVal);
            ps.setTimestamp(11, Timestamp.valueOf(now));
            ps.setTimestamp(12, Timestamp.valueOf(now));

            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            }
        } catch (SQLException e) {
            log.error("Failed to insert scan record", e);
        }
        return 0;
    }

    public boolean updateScanStatus(long scanId, String status) {
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(UPDATE_STATUS)) {

            ps.setString(1, status);
            ps.setLong(2, scanId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            log.error("Failed to update status for scan id={}", scanId, e);
            return false;
        }
    }

    public boolean updateScanProgress(long scanId, int pagesDiscovered, int pagesTested, int findingsCount) {
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(UPDATE_PROGRESS)) {

            ps.setInt(1, pagesDiscovered);
            ps.setInt(2, pagesTested);
            ps.setInt(3, findingsCount);
            ps.setLong(4, scanId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            log.error("Failed to update progress for scan id={}", scanId, e);
            return false;
        }
    }

    public boolean completeScan(long scanId, String status, int pagesDiscovered, int pagesTested,
                                int findingsCount, String errorMessage) {
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(COMPLETE_SCAN)) {

            ps.setString(1, status);
            ps.setInt(2, pagesDiscovered);
            ps.setInt(3, pagesTested);
            ps.setInt(4, findingsCount);
            ps.setTimestamp(5, Timestamp.valueOf(LocalDateTime.now()));
            ps.setString(6, errorMessage);
            ps.setLong(7, scanId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            log.error("Failed to finalize scan id={}", scanId, e);
            return false;
        }
    }

    public boolean deleteScan(long scanId, int userId) {
        String deleteSql = "DELETE FROM scans WHERE id = ? AND user_id = ?";
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(deleteSql)) {

            ps.setLong(1, scanId);
            ps.setInt(2, userId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            log.error("Failed to delete scan id={} for user={}", scanId, userId, e);
            return false;
        }
    }

    private ScanRecord mapRow(ResultSet rs) throws SQLException {
        ScanRecord s = new ScanRecord();
        s.setId(rs.getLong("id"));
        s.setWebsiteId(rs.getLong("website_id"));
        s.setWebsiteName(rs.getString("website_name"));
        s.setUserId(rs.getInt("user_id"));
        s.setStatus(rs.getString("status"));
        s.setCrawlDepth(rs.getInt("crawl_depth"));
        s.setMaxPages(rs.getInt("max_pages"));
        s.setTimeoutSeconds(rs.getInt("timeout_seconds"));
        s.setPagesDiscovered(rs.getInt("pages_discovered"));
        s.setPagesTested(rs.getInt("pages_tested"));
        s.setFindingsCount(rs.getInt("findings_count"));

        Timestamp started = rs.getTimestamp("started_at");
        if (started != null) s.setStartedAt(started.toLocalDateTime());

        Timestamp completed = rs.getTimestamp("completed_at");
        if (completed != null) s.setCompletedAt(completed.toLocalDateTime());

        Timestamp created = rs.getTimestamp("created_at");
        if (created != null) s.setCreatedAt(created.toLocalDateTime());

        return s;
    }
}
