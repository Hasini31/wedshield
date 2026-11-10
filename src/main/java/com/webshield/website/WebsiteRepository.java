package com.webshield.website;

import com.webshield.config.DatabaseConfig;
import com.webshield.models.Website;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/**
 * JDBC persistence repository for {@link Website} entities.
 * Ensures all operations are scoped to the authenticated user.
 */
@Repository
public class WebsiteRepository {

    private static final Logger log = LoggerFactory.getLogger(WebsiteRepository.class);

    private static final String INSERT_SQL = """
            INSERT INTO websites (user_id, name, url, description, is_authorized, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """;

    private static final String UPDATE_SQL = """
            UPDATE websites
            SET name = ?, url = ?, description = ?, is_authorized = ?, status = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
            """;

    private static final String DELETE_SQL = """
            DELETE FROM websites WHERE id = ? AND user_id = ?
            """;

    private static final String SELECT_BY_ID = """
            SELECT w.id, w.user_id, w.name, w.url, w.description, w.is_authorized, w.status,
                   w.last_scan_at, w.created_at, w.updated_at,
                   COALESCE(SUM(s.findings_count), 0) AS total_findings,
                   COALESCE(MAX(s.pages_discovered), 0) AS total_pages
            FROM websites w
            LEFT JOIN scans s ON s.website_id = w.id
            WHERE w.id = ? AND w.user_id = ?
            GROUP BY w.id, w.user_id, w.name, w.url, w.description, w.is_authorized, w.status,
                     w.last_scan_at, w.created_at, w.updated_at
            """;

    private static final String SELECT_ALL_BY_USER = """
            SELECT w.id, w.user_id, w.name, w.url, w.description, w.is_authorized, w.status,
                   w.last_scan_at, w.created_at, w.updated_at,
                   COALESCE(SUM(s.findings_count), 0) AS total_findings,
                   COALESCE(MAX(s.pages_discovered), 0) AS total_pages
            FROM websites w
            LEFT JOIN scans s ON s.website_id = w.id
            WHERE w.user_id = ?
            GROUP BY w.id, w.user_id, w.name, w.url, w.description, w.is_authorized, w.status,
                     w.last_scan_at, w.created_at, w.updated_at
            ORDER BY w.created_at DESC
            """;

    private static final String CHECK_EXISTS = """
            SELECT COUNT(*) FROM websites WHERE url = ? AND user_id = ? AND (? IS NULL OR id != ?)
            """;

    public Website save(Website website) {
        LocalDateTime now = LocalDateTime.now();
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement stmt = conn.prepareStatement(INSERT_SQL, Statement.RETURN_GENERATED_KEYS)) {

            stmt.setInt(1, website.getUserId());
            stmt.setString(2, website.getName());
            stmt.setString(3, website.getUrl());
            stmt.setString(4, website.getDescription());
            stmt.setBoolean(5, website.isAuthorized());
            stmt.setString(6, website.getStatus());
            stmt.setTimestamp(7, Timestamp.valueOf(now));
            stmt.setTimestamp(8, Timestamp.valueOf(now));

            stmt.executeUpdate();

            try (ResultSet rs = stmt.getGeneratedKeys()) {
                if (rs.next()) {
                    website.setId(rs.getLong(1));
                }
            }
            website.setCreatedAt(now);
            website.setUpdatedAt(now);
            return website;
        } catch (SQLException e) {
            log.error("Failed to save website: {}", website.getUrl(), e);
            throw new RuntimeException("Database error saving website: " + e.getMessage(), e);
        }
    }

    public boolean update(Website website) {
        LocalDateTime now = LocalDateTime.now();
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement stmt = conn.prepareStatement(UPDATE_SQL)) {

            stmt.setString(1, website.getName());
            stmt.setString(2, website.getUrl());
            stmt.setString(3, website.getDescription());
            stmt.setBoolean(4, website.isAuthorized());
            stmt.setString(5, website.getStatus());
            stmt.setTimestamp(6, Timestamp.valueOf(now));
            stmt.setLong(7, website.getId());
            stmt.setInt(8, website.getUserId());

            int updated = stmt.executeUpdate();
            if (updated > 0) {
                website.setUpdatedAt(now);
                return true;
            }
            return false;
        } catch (SQLException e) {
            log.error("Failed to update website id: {}", website.getId(), e);
            throw new RuntimeException("Database error updating website: " + e.getMessage(), e);
        }
    }

    public boolean delete(long websiteId, int userId) {
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement stmt = conn.prepareStatement(DELETE_SQL)) {

            stmt.setLong(1, websiteId);
            stmt.setInt(2, userId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            log.error("Failed to delete website id: {} for user: {}", websiteId, userId, e);
            throw new RuntimeException("Database error deleting website: " + e.getMessage(), e);
        }
    }

    public Optional<Website> findById(long websiteId, int userId) {
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement stmt = conn.prepareStatement(SELECT_BY_ID)) {

            stmt.setLong(1, websiteId);
            stmt.setInt(2, userId);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapRow(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Failed to find website id: {} for user: {}", websiteId, userId, e);
        }
        return Optional.empty();
    }

    public List<Website> findAllByUserId(int userId) {
        List<Website> websites = new ArrayList<>();
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement stmt = conn.prepareStatement(SELECT_ALL_BY_USER)) {

            stmt.setInt(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    websites.add(mapRow(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Failed to query websites for user: {}", userId, e);
        }
        return websites;
    }

    public boolean existsByUrlAndUserId(String url, int userId, Long excludeWebsiteId) {
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement stmt = conn.prepareStatement(CHECK_EXISTS)) {

            stmt.setString(1, url);
            stmt.setInt(2, userId);
            if (excludeWebsiteId != null) {
                stmt.setLong(3, excludeWebsiteId);
                stmt.setLong(4, excludeWebsiteId);
            } else {
                stmt.setNull(3, Types.BIGINT);
                stmt.setNull(4, Types.BIGINT);
            }

            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next() && rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            log.error("Failed to check duplicate website url: {}", url, e);
            return false;
        }
    }

    private Website mapRow(ResultSet rs) throws SQLException {
        Website w = new Website();
        w.setId(rs.getLong("id"));
        w.setUserId(rs.getInt("user_id"));
        w.setName(rs.getString("name"));
        w.setUrl(rs.getString("url"));
        w.setDescription(rs.getString("description"));
        w.setAuthorized(rs.getBoolean("is_authorized"));
        w.setStatus(rs.getString("status"));

        Timestamp lastScan = rs.getTimestamp("last_scan_at");
        if (lastScan != null) w.setLastScanAt(lastScan.toLocalDateTime());

        Timestamp created = rs.getTimestamp("created_at");
        if (created != null) w.setCreatedAt(created.toLocalDateTime());

        Timestamp updated = rs.getTimestamp("updated_at");
        if (updated != null) w.setUpdatedAt(updated.toLocalDateTime());

        w.setFindingCount(rs.getInt("total_findings"));
        w.setPageCount(rs.getInt("total_pages"));
        return w;
    }
}

