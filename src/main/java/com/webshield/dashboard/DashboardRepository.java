package com.webshield.dashboard;

import com.webshield.config.DatabaseConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.sql.*;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * JDBC repository supplying all telemetry, metrics, and activity data
 * for the WebShield Unified Security Command Center Dashboard.
 *
 * <p>All queries are strictly scoped to the authenticated user's ID
 * to preserve multi-tenant isolation.
 */
@Repository
public class DashboardRepository {

    private static final Logger log = LoggerFactory.getLogger(DashboardRepository.class);
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm");

    private Connection getConnection() throws SQLException {
        return DatabaseConfig.getInstance().getConnection();
    }

    /* ------------------------------------------------------------------
     * Unified Statistics
     * ------------------------------------------------------------------ */

    public DashboardStatistics loadStatistics(int userId) {
        return loadUnifiedStatistics(userId);
    }

    public DashboardStatistics loadUnifiedStatistics(int userId) {
        // 1. Websites count & active count
        int totalWebsites = 0;
        int activeWebsites = 0;
        String sqlWebsites = "SELECT COUNT(*), COALESCE(SUM(CASE WHEN status = 'ACTIVE' THEN 1 ELSE 0 END), 0) FROM websites WHERE user_id = ?";
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sqlWebsites)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    totalWebsites = rs.getInt(1);
                    activeWebsites = rs.getInt(2);
                }
            }
        } catch (SQLException e) {
            log.error("loadUnifiedStatistics: websites failed", e);
        }

        // 2. API Projects count & endpoints count
        int totalApiProjects = 0;
        int totalApiEndpoints = 0;
        String sqlApiProjects = "SELECT COUNT(*), COALESCE(SUM(endpoints_count), 0) FROM api_projects WHERE user_id = ?";
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sqlApiProjects)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    totalApiProjects = rs.getInt(1);
                    totalApiEndpoints = rs.getInt(2);
                }
            }
        } catch (SQLException e) {
            log.error("loadUnifiedStatistics: api_projects failed", e);
        }

        // 3. Website Scans stats
        int totalWebsiteScans = 0;
        int websitesScanned = 0;
        int totalPagesDiscovered = 0;
        int totalPagesTested = 0;
        int totalWebsiteFindings = 0;
        String lastWebsiteScanDate = "—";
        String sqlWebScans = """
            SELECT COUNT(*), COUNT(DISTINCT website_id),
                   COALESCE(SUM(pages_discovered), 0),
                   COALESCE(SUM(pages_tested), 0),
                   COALESCE(SUM(findings_count), 0),
                   MAX(created_at)
            FROM scans WHERE user_id = ?
            """;
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sqlWebScans)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    totalWebsiteScans = rs.getInt(1);
                    websitesScanned = rs.getInt(2);
                    totalPagesDiscovered = rs.getInt(3);
                    totalPagesTested = rs.getInt(4);
                    totalWebsiteFindings = rs.getInt(5);
                    Timestamp maxCreated = rs.getTimestamp(6);
                    if (maxCreated != null) {
                        lastWebsiteScanDate = maxCreated.toLocalDateTime().format(FMT);
                    }
                }
            }
        } catch (SQLException e) {
            log.error("loadUnifiedStatistics: scans failed", e);
        }

        // 4. API Scans stats
        int totalApiScans = 0;
        int apiTestCasesGenerated = 0;
        int apiTestCasesExecuted = 0;
        int totalApiFindings = 0;
        int criticalApiFindings = 0;
        String sqlApiScans = """
            SELECT COUNT(*),
                   COALESCE(SUM(total_generated_test_cases), 0),
                   COALESCE(SUM(total_executed_requests), 0),
                   COALESCE(SUM(total_findings), 0),
                   COALESCE(SUM(critical_count), 0)
            FROM api_scans WHERE user_id = ?
            """;
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sqlApiScans)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    totalApiScans = rs.getInt(1);
                    apiTestCasesGenerated = rs.getInt(2);
                    apiTestCasesExecuted = rs.getInt(3);
                    totalApiFindings = rs.getInt(4);
                    criticalApiFindings = rs.getInt(5);
                }
            }
        } catch (SQLException e) {
            log.error("loadUnifiedStatistics: api_scans failed", e);
        }

        // 5. Website Findings by Severity
        Map<String, Integer> webSeverity = loadSeverityMap("scan_findings", "scans", userId);
        int criticalWebsiteFindings = webSeverity.getOrDefault("CRITICAL", 0);

        // 6. API Findings by Severity
        Map<String, Integer> apiSeverity = loadSeverityMap("api_findings", "api_scans", userId);

        // 7. Combined Severity Map
        Map<String, Integer> combinedSeverity = new LinkedHashMap<>();
        for (String sev : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")) {
            combinedSeverity.put(sev, webSeverity.getOrDefault(sev, 0) + apiSeverity.getOrDefault(sev, 0));
        }

        int totalScans = totalWebsiteScans + totalApiScans;
        int totalFindings = totalWebsiteFindings + totalApiFindings;
        int criticalFindings = criticalWebsiteFindings + criticalApiFindings;

        // 8. API Category Distribution
        List<ApiCategoryStat> categoryStats = loadApiCategoryStats(userId);

        return new DashboardStatistics(
                totalWebsites, activeWebsites, totalApiProjects,
                totalWebsiteScans, totalApiScans, totalScans,
                apiTestCasesGenerated, apiTestCasesExecuted,
                totalWebsiteFindings, totalApiFindings, totalFindings,
                criticalWebsiteFindings, criticalApiFindings, criticalFindings,
                webSeverity, apiSeverity, combinedSeverity,
                websitesScanned, totalPagesDiscovered, totalPagesTested,
                lastWebsiteScanDate, totalApiEndpoints, categoryStats
        );
    }

    private Map<String, Integer> loadSeverityMap(String findingTable, String scanTable, int userId) {
        String sql = "SELECT f.severity, COUNT(*) AS cnt FROM " + findingTable + " f JOIN " +
                scanTable + " s ON f.scan_id = s.id WHERE s.user_id = ? GROUP BY f.severity";
        Map<String, Integer> map = new LinkedHashMap<>();
        for (String s : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")) {
            map.put(s, 0);
        }
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String sev = rs.getString("severity");
                    if (sev != null) {
                        map.put(sev.toUpperCase(), rs.getInt("cnt"));
                    }
                }
            }
        } catch (SQLException e) {
            log.error("loadSeverityMap failed for table: {}", findingTable, e);
        }
        return map;
    }

    /* ------------------------------------------------------------------
     * API Category Distribution (Section C)
     * ------------------------------------------------------------------ */

    public List<ApiCategoryStat> loadApiCategoryStats(int userId) {
        List<String> categories = List.of(
                "VALID_SMOKE", "BOUNDARY", "MISSING_REQUIRED", "TYPE_CONFUSION", "SECURITY_PROBES");

        Map<String, Integer> generatedMap = new LinkedHashMap<>();
        Map<String, Integer> executedMap = new LinkedHashMap<>();
        Map<String, Integer> findingsMap = new LinkedHashMap<>();
        for (String cat : categories) {
            generatedMap.put(cat, 0);
            executedMap.put(cat, 0);
            findingsMap.put(cat, 0);
        }

        // Generated counts per category
        String sqlGen = """
            SELECT tc.category, COUNT(*) AS cnt
            FROM api_test_case_results tc
            JOIN api_scans s ON tc.scan_id = s.id
            WHERE s.user_id = ?
            GROUP BY tc.category
            """;
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sqlGen)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String cat = rs.getString("category");
                    if (cat != null) generatedMap.put(cat.toUpperCase(), rs.getInt("cnt"));
                }
            }
        } catch (SQLException e) {
            log.debug("loadApiCategoryStats: sqlGen info: {}", e.getMessage());
        }

        // Executed counts per category
        String sqlExec = """
            SELECT tc.category, COUNT(DISTINCT e.id) AS cnt
            FROM api_test_case_results tc
            JOIN api_scans s ON tc.scan_id = s.id
            JOIN api_executions e ON e.scan_id = tc.scan_id AND e.test_case_id = tc.test_case_id
            WHERE s.user_id = ?
            GROUP BY tc.category
            """;
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sqlExec)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String cat = rs.getString("category");
                    if (cat != null) executedMap.put(cat.toUpperCase(), rs.getInt("cnt"));
                }
            }
        } catch (SQLException e) {
            log.debug("loadApiCategoryStats: sqlExec info: {}", e.getMessage());
        }

        // Findings per category
        String sqlFind = """
            SELECT tc.category, COUNT(DISTINCT f.id) AS cnt
            FROM api_findings f
            JOIN api_executions e ON f.execution_uuid = e.execution_uuid
            JOIN api_test_case_results tc ON e.scan_id = tc.scan_id AND e.test_case_id = tc.test_case_id
            JOIN api_scans s ON f.scan_id = s.id
            WHERE s.user_id = ?
            GROUP BY tc.category
            """;
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sqlFind)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String cat = rs.getString("category");
                    if (cat != null) findingsMap.put(cat.toUpperCase(), rs.getInt("cnt"));
                }
            }
        } catch (SQLException e) {
            log.debug("loadApiCategoryStats: sqlFind info: {}", e.getMessage());
        }

        List<ApiCategoryStat> list = new ArrayList<>();
        for (String cat : categories) {
            list.add(new ApiCategoryStat(
                    cat,
                    generatedMap.getOrDefault(cat, 0),
                    executedMap.getOrDefault(cat, 0),
                    findingsMap.getOrDefault(cat, 0)
            ));
        }
        return list;
    }

    /* ------------------------------------------------------------------
     * Website Overview Table (Section B, Top 5)
     * ------------------------------------------------------------------ */

    public List<WebsiteOverviewRow> loadWebsiteOverview(int userId) {
        String sql = """
            SELECT w.id, w.name, w.url, w.status,
                   COALESCE(s.pages_discovered, 0) AS pages_discovered,
                   COALESCE(s.pages_tested, 0) AS pages_tested,
                   COALESCE(s.findings_count, 0) AS findings_count,
                   (SELECT COUNT(*) FROM scan_findings sf WHERE sf.scan_id = s.id AND sf.severity = 'CRITICAL') AS crit_count,
                   (SELECT COUNT(*) FROM scan_findings sf WHERE sf.scan_id = s.id AND sf.severity = 'HIGH') AS high_count,
                   s.created_at AS last_scan_date,
                   s.status AS scan_status,
                   s.id AS last_scan_id
            FROM websites w
            LEFT JOIN scans s ON s.id = (
                SELECT s2.id FROM scans s2 WHERE s2.website_id = w.id ORDER BY s2.created_at DESC LIMIT 1
            )
            WHERE w.user_id = ?
            ORDER BY w.updated_at DESC, w.created_at DESC
            LIMIT 5
            """;
        List<WebsiteOverviewRow> rows = new ArrayList<>();
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Timestamp scanTs = rs.getTimestamp("last_scan_date");
                    long scanId = rs.getLong("last_scan_id");
                    rows.add(new WebsiteOverviewRow(
                            rs.getLong("id"),
                            rs.getString("name"),
                            rs.getString("url"),
                            rs.getInt("pages_discovered"),
                            rs.getInt("pages_tested"),
                            rs.getInt("findings_count"),
                            rs.getInt("crit_count"),
                            rs.getInt("high_count"),
                            scanTs != null ? scanTs.toLocalDateTime().format(FMT) : "Not Scanned",
                            rs.getString("scan_status") != null ? rs.getString("scan_status") : "IDLE",
                            scanId > 0 ? scanId : null
                    ));
                }
            }
        } catch (SQLException e) {
            log.error("loadWebsiteOverview failed", e);
        }
        return rows;
    }

    /* ------------------------------------------------------------------
     * Recent Security Activity (Section E, Top 10 unified)
     * ------------------------------------------------------------------ */

    public List<SecurityActivityRow> loadRecentSecurityActivity(int userId) {
        String sql = """
            (
              SELECT s.id AS raw_id,
                     CONCAT('WS-#', s.id) AS scan_id_display,
                     w.name AS target_name,
                     'WEBSITE' AS target_type,
                     s.created_at AS scan_date,
                     TIMESTAMPDIFF(SECOND, s.started_at, s.completed_at) AS duration_sec,
                     CONCAT(s.pages_tested, ' pages') AS units_tested,
                     s.findings_count AS findings_count,
                     s.status AS scan_status
              FROM scans s
              JOIN websites w ON s.website_id = w.id
              WHERE s.user_id = ?
            )
            UNION ALL
            (
              SELECT s.id AS raw_id,
                     CONCAT('API-#', s.id) AS scan_id_display,
                     p.name AS target_name,
                     'API' AS target_type,
                     s.created_at AS scan_date,
                     ROUND(s.duration_ms / 1000.0, 1) AS duration_sec,
                     CONCAT(s.total_executed_requests, ' reqs') AS units_tested,
                     s.total_findings AS findings_count,
                     s.status AS scan_status
              FROM api_scans s
              JOIN api_projects p ON s.api_project_id = p.id
              WHERE s.user_id = ?
            )
            ORDER BY scan_date DESC
            LIMIT 10
            """;
        List<SecurityActivityRow> rows = new ArrayList<>();
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, userId);
            ps.setInt(2, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Timestamp ts = rs.getTimestamp("scan_date");
                    double dur = rs.getDouble("duration_sec");
                    String durStr = dur > 0 ? String.format("%.1fs", dur) : "<1s";
                    rows.add(new SecurityActivityRow(
                            rs.getLong("raw_id"),
                            rs.getString("scan_id_display"),
                            rs.getString("target_name"),
                            rs.getString("target_type"),
                            ts != null ? ts.toLocalDateTime().format(FMT) : "—",
                            durStr,
                            rs.getString("units_tested"),
                            rs.getInt("findings_count"),
                            rs.getString("scan_status")
                    ));
                }
            }
        } catch (SQLException e) {
            log.error("loadRecentSecurityActivity failed", e);
        }
        return rows;
    }

    /* ------------------------------------------------------------------
     * Critical Security Findings (Section F, Top 5 unresolved)
     * ------------------------------------------------------------------ */

    public List<CriticalFindingRow> loadCriticalFindings(int userId) {
        String sql = """
            (
              SELECT sf.id AS finding_id,
                     sf.finding_name,
                     w.name AS target_name,
                     'WEBSITE' AS target_type,
                     COALESCE(v.category, 'Web Security') AS category,
                     sf.severity,
                     sf.status AS confidence,
                     'OPEN' AS review_status,
                     sf.detected_at,
                     s.id AS scan_id
              FROM scan_findings sf
              JOIN scans s ON sf.scan_id = s.id
              JOIN websites w ON s.website_id = w.id
              LEFT JOIN vulnerabilities v ON sf.vulnerability_id = v.id
              WHERE s.user_id = ? AND sf.severity IN ('CRITICAL', 'HIGH')
            )
            UNION ALL
            (
              SELECT af.id AS finding_id,
                     af.title AS finding_name,
                     p.name AS target_name,
                     'API' AS target_type,
                     af.owasp_category AS category,
                     af.severity,
                     af.confidence,
                     af.lifecycle_status AS review_status,
                     af.detected_at,
                     s.id AS scan_id
              FROM api_findings af
              JOIN api_scans s ON af.scan_id = s.id
              JOIN api_projects p ON af.api_project_id = p.id
              WHERE s.user_id = ? AND af.severity IN ('CRITICAL', 'HIGH')
                    AND af.lifecycle_status != 'RESOLVED'
            )
            ORDER BY detected_at DESC
            LIMIT 5
            """;
        List<CriticalFindingRow> rows = new ArrayList<>();
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, userId);
            ps.setInt(2, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    rows.add(new CriticalFindingRow(
                            rs.getLong("finding_id"),
                            rs.getString("finding_name"),
                            rs.getString("target_name"),
                            rs.getString("target_type"),
                            rs.getString("category"),
                            rs.getString("severity"),
                            rs.getString("confidence"),
                            rs.getString("review_status"),
                            rs.getLong("scan_id")
                    ));
                }
            }
        } catch (SQLException e) {
            log.error("loadCriticalFindings failed", e);
        }
        return rows;
    }

    /* ------------------------------------------------------------------
     * Legacy Recent Websites (for backward compatibility)
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
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
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
     * Legacy Recent Scans (for backward compatibility)
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
        try (Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
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
