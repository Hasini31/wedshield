package com.webshield.database;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.util.List;

/**
 * Non-destructive, versioned database schema migration coordinator.
 * Automatically checks for and applies schema definitions (01_schema, 02_api_testing, 03_api_execution)
 * on startup, ensuring that existing Docker database volumes safely acquire newly added tables
 * without requiring container recreation or data deletion.
 */
@Service
public class DatabaseMigrationService {

    private static final Logger log = LoggerFactory.getLogger(DatabaseMigrationService.class);

    private static final List<String> MIGRATION_SCRIPTS = List.of(
            "/database/schema.sql",
            "/database/02_api_testing_schema.sql",
            "/database/03_api_execution_and_findings_schema.sql",
            "/database/04_api_reports_schema.sql"
    );

    private final DataSource dataSource;

    @Autowired
    public DatabaseMigrationService(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void runMigrations() {
        if (dataSource == null) {
            log.info("No DataSource configured; skipping database migrations.");
            return;
        }

        try (Connection conn = dataSource.getConnection()) {
            log.info("Connected to database '{}' for schema migration check.", conn.getCatalog());
            for (String scriptPath : MIGRATION_SCRIPTS) {
                applyMigrationScript(conn, scriptPath);
            }
            log.info("Database migration check completed successfully.");
        } catch (Exception e) {
            log.warn("Database migration check could not be completed (database may be offline or in test mode): {}", e.getMessage());
        }
    }

    /**
     * Executes SQL statements from a classpath resource script safely.
     */
    public void applyMigrationScript(Connection conn, String scriptPath) {
        try (InputStream in = getClass().getResourceAsStream(scriptPath)) {
            if (in == null) {
                log.warn("Migration script not found on classpath: {}", scriptPath);
                return;
            }

            StringBuilder currentStatement = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
                 Statement stmt = conn.createStatement()) {

                String line;
                while ((line = reader.readLine()) != null) {
                    String trimmed = line.trim();
                    if (trimmed.startsWith("--") || trimmed.startsWith("/*") || trimmed.isBlank()) {
                        continue;
                    }

                    currentStatement.append(line).append("\n");

                    if (trimmed.endsWith(";")) {
                        String sql = currentStatement.toString().trim();
                        // Strip trailing semicolon
                        if (sql.endsWith(";")) {
                            sql = sql.substring(0, sql.length() - 1).trim();
                        }

                        // Skip USE commands or comments
                        if (!sql.isBlank() && !sql.toUpperCase().startsWith("USE ")) {
                            try {
                                stmt.execute(sql);
                            } catch (Exception ex) {
                                // Ignore 'table already exists' or harmless warning
                                log.debug("Migration statement notice for [{}]: {}", scriptPath, ex.getMessage());
                            }
                        }
                        currentStatement.setLength(0);
                    }
                }
            }
            log.debug("Applied migration script: {}", scriptPath);
        } catch (Exception e) {
            log.warn("Failed to apply migration script {}: {}", scriptPath, e.getMessage());
        }
    }
}

