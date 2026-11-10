package com.webshield.database.repositories;

import com.webshield.models.User;
import com.webshield.config.DatabaseConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/**
 * Simple JDBC repository for {@link User} entities.
 * Uses {@link DatabaseConfig} for connections.
 */
@Repository
public class UserRepository {
    private static final Logger log = LoggerFactory.getLogger(UserRepository.class);
    private static final String INSERT_SQL = "INSERT INTO users (full_name, email, password_hash, created_at, updated_at) VALUES (?,?,?,?,?)";
    private static final String SELECT_BY_EMAIL = "SELECT id, id AS user_id, full_name, email, password_hash, created_at, updated_at FROM users WHERE email = ?";
    private static final String SELECT_BY_ID = "SELECT id, id AS user_id, full_name, email, password_hash, created_at, updated_at FROM users WHERE id = ?";

    public void save(User user) {
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement stmt = conn.prepareStatement(INSERT_SQL, Statement.RETURN_GENERATED_KEYS)) {
            LocalDateTime now = LocalDateTime.now();
            stmt.setString(1, user.getFullName());
            stmt.setString(2, user.getEmail());
            stmt.setString(3, user.getPasswordHash());
            stmt.setTimestamp(4, Timestamp.valueOf(now));
            stmt.setTimestamp(5, Timestamp.valueOf(now));
            stmt.executeUpdate();
            try (ResultSet rs = stmt.getGeneratedKeys()) {
                if (rs.next()) {
                    user.setId(rs.getInt(1));
                }
            }
            user.setCreatedAt(now);
            user.setUpdatedAt(now);
        } catch (SQLException e) {
            log.error("Failed to save user", e);
            throw new RuntimeException(e);
        }
    }

    public Optional<User> findByEmail(String email) {
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement stmt = conn.prepareStatement(SELECT_BY_EMAIL)) {
            stmt.setString(1, email);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapRow(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Failed to query user by email", e);
            throw new RuntimeException(e);
        }
        return Optional.empty();
    }

    public Optional<User> findById(int id) {
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement stmt = conn.prepareStatement(SELECT_BY_ID)) {
            stmt.setInt(1, id);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapRow(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Failed to query user by id", e);
            throw new RuntimeException(e);
        }
        return Optional.empty();
    }

    private User mapRow(ResultSet rs) throws SQLException {
        User u = new User();
        try {
            u.setId(rs.getInt("id"));
        } catch (SQLException e) {
            u.setId(rs.getInt("user_id"));
        }
        u.setFullName(rs.getString("full_name"));
        u.setEmail(rs.getString("email"));
        u.setPasswordHash(rs.getString("password_hash"));
        u.setCreatedAt(rs.getTimestamp("created_at").toLocalDateTime());
        u.setUpdatedAt(rs.getTimestamp("updated_at").toLocalDateTime());
        return u;
    }
}

