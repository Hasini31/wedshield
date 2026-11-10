package com.webshield.dashboard;

import com.webshield.config.DatabaseConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository that supplies all data shown on the Dashboard.
 * Every query is scoped to a specific user_id so users can never see
 * another user's data.
 *
 * <p>All SQL uses {@link PreparedStatement} to prevent injection.
 * Resources are closed via try-with-resources.
 */
@Repository
public class DashboardRepository {

    private static final Logger log = LoggerFactory.getLogger(DashboardRepository.class);
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm");

    /* ------------------------------------------------------------------
     * Summary statistics
     * ------------------------------------------------------------------ */

    /**
     * Aggregated statistics for the overview cards.
     * All values default to 0 when the DB contains no rows for this user.
     */
    public DashboardStatistics loadStatistics(int userId) {
        int websites   = countTable("websites",     userId);
        int scans      = countTable("scans",        userId);
        int findings   = countFindings(userId, null);
        int critical   = countFindings(userId, "CRITICAL");
        Map<String, Integer> bySeverity = findingsBySeverity(userId);
        return new DashboardStatistics(websites, scans, findings, critical, bySeverity);
    }

    private int countTable(String table, int userId) {
        String sql = "SELECT COUNT(*) FROM " + table + " WHERE user_id = ?";
        try (Connection c = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        } catch (SQLException e) {
            log.error("countTable({}) failed", table, e);
            return 0;
        }
    }

    private int countFindings(int userId, String severity) {
        String sql = severity == null
                ? "SELECT COUNT(*) FROM scan_findings sf JOIN scans s ON sf.scan_id = s.id WHERE s.user_id = ?"
                : "SELECT COUNT(*) FROM scan_findings sf JOIN scans s ON sf.scan_id = s.id WHERE s.user_id = ? AND sf.severity = ?";
        try (Connection c = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, userId);
            if (severity != null) ps.setString(2, severity);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        } catch (SQLException e) {
            log.error("countFindings(severity={}) failed", severity, e);
            return 0;
        }
    }

    private Map<String, Integer> findingsBySeverity(int userId) {
        String sql = """
                SELECT sf.severity, COUNT(*) AS cnt
                FROM scan_findings sf
                JOIN scans s ON sf.scan_id = s.id
                WHERE s.user_id = ?
                GROUP BY sf.severity
                """;
        Map<String, Integer> result = new LinkedHashMap<>();
        // Pre-populate all categories with 0 so chart always has 5 entries
        for (String sev : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")) {
            result.put(sev, 0);
        }
        try (Connection c = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    result.put(rs.getString("severity"), rs.getInt("cnt"));
                }
            }
        } catch (SQLException e) {
            log.error("findingsBySeverity failed", e);
        }
        return result;
    }

    /* ------------------------------------------------------------------
     * Recent websites (latest 5 by created_at)
     * ------------------------------------------------------------------ */

    public List<WebsiteRow> loadRecentWebsites(int userId) {
        String sql = """
                SELECT w.id, w.name, w.url,
                       w.created_at,
                       MAX(s.created_at) AS last_scan_at,
                       w.status
                FROM websites w
                LEFT JOIN scans s ON s.website_id = w.id
                WHERE w.user_id = ?
                GROUP BY w.id, w.name, w.url, w.created_at, w.status
                ORDER BY w.created_at DESC
                LIMIT 5
                """;
        List<WebsiteRow> rows = new ArrayList<>();
        try (Connection c = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Timestamp created  = rs.getTimestamp("created_at");
                    Timestamp lastScan = rs.getTimestamp("last_scan_at");
                    rows.add(new WebsiteRow(
                            rs.getLong("id"),
                            rs.getString("name"),
                            rs.getString("url"),
                            created  != null ? created.toLocalDateTime().format(FMT)  : "—",
                            lastScan != null ? lastScan.toLocalDateTime().format(FMT) : "Not scanned",
                            rs.getString("status")
                    ));
                }
            }
        } catch (SQLException e) {
            log.error("loadRecentWebsites failed", e);
        }
        return rows;
    }

    /* ------------------------------------------------------------------
     * Recent scans (latest 5 by created_at)
     * ------------------------------------------------------------------ */

    public List<ScanRow> loadRecentScans(int userId) {
        String sql = """
                SELECT s.id, w.name AS website_name,
                       s.started_at, s.status, s.findings_count
                FROM scans s
                JOIN websites w ON s.website_id = w.id
                WHERE s.user_id = ?
                ORDER BY s.created_at DESC
                LIMIT 5
                """;
        List<ScanRow> rows = new ArrayList<>();
        try (Connection c = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Timestamp started = rs.getTimestamp("started_at");
                    rows.add(new ScanRow(
                            rs.getLong("id"),
                            rs.getString("website_name"),
                            started != null ? started.toLocalDateTime().format(FMT) : "—",
                            rs.getString("status"),
                            rs.getInt("findings_count")
                    ));
                }
            }
        } catch (SQLException e) {
            log.error("loadRecentScans failed", e);
        }
        return rows;
    }
}

