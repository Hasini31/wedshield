package com.webshield.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

/**
 * DatabaseConfig – central JDBC connection provider for WebShield.
 *
 * <p>Reads connection parameters from {@code /database.properties} on the
 * classpath. The properties file is excluded from version control via
 * {@code .gitignore}; a template is committed as
 * {@code database.properties.template}.
 *
 * <p>In Stage 3 this class will be extended with a lightweight connection
 * pool (manual FIFO queue backed by {@link java.util.ArrayDeque}) to avoid
 * opening a new {@link Connection} on every database call.
 *
 * <p>Usage:
 * <pre>{@code
 *   try (Connection conn = DatabaseConfig.getInstance().getConnection()) {
 *       // execute JDBC operations
 *   }
 * }</pre>
 */
public final class DatabaseConfig {

    private static final Logger log = LoggerFactory.getLogger(DatabaseConfig.class);
    private static final String PROPS_PATH = "/database.properties";

    // Singleton
    private static volatile DatabaseConfig instance;

    private final String jdbcUrl;
    private final String username;
    private final String password;

    /* ------------------------------------------------------------------ */
    /* Constructors                                                       */
    /* ------------------------------------------------------------------ */

    private DatabaseConfig() {
        String envUrl = System.getenv("DB_URL");
        String envUser = System.getenv("DB_USER");
        String envPass = System.getenv("DB_PASSWORD");

        if (envUrl != null && !envUrl.isBlank()) {
            this.jdbcUrl = envUrl;
            this.username = envUser != null ? envUser : "webshield_user";
            this.password = envPass != null ? envPass : "webshield_pass_2024";
            log.info("DatabaseConfig loaded from environment variables — url: {}", jdbcUrl);
            return;
        }

        Properties props = new Properties();
        try (InputStream in = getClass().getResourceAsStream(PROPS_PATH)) {
            if (in != null) {
                props.load(in);
            }
        } catch (IOException e) {
            log.warn("Failed to load {}, falling back to defaults", PROPS_PATH);
        }

        this.jdbcUrl  = props.getProperty("db.url", "jdbc:mysql://localhost:3306/webshield?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC");
        this.username = props.getProperty("db.username", "webshield_user");
        this.password = props.getProperty("db.password", "webshield_pass_2024");

        log.info("DatabaseConfig loaded — url: {}", jdbcUrl);
    }

    /**
     * Package-visible / public constructor for testing or custom configuration.
     */
    public DatabaseConfig(String jdbcUrl, String username, String password) {
        this.jdbcUrl = jdbcUrl;
        this.username = username;
        this.password = password;
    }

    /* ------------------------------------------------------------------ */
    /* Public API                                                         */
    /* ------------------------------------------------------------------ */

    /**
     * Returns the singleton instance, creating it on first call.
     */
    public static DatabaseConfig getInstance() {
        if (instance == null) {
            synchronized (DatabaseConfig.class) {
                if (instance == null) {
                    instance = new DatabaseConfig();
                }
            }
        }
        return instance;
    }

    /**
     * Overrides the singleton instance, typically for testing.
     */
    public static void setInstance(DatabaseConfig customInstance) {
        synchronized (DatabaseConfig.class) {
            instance = customInstance;
        }
    }

    /**
     * Resets the singleton instance so it will reload from database.properties next time.
     */
    public static void resetInstance() {
        synchronized (DatabaseConfig.class) {
            instance = null;
        }
    }

    /**
     * Opens and returns a new JDBC {@link Connection}.
     * The caller is responsible for closing it (use try-with-resources).
     *
     * @throws SQLException if the connection cannot be established
     */
    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(jdbcUrl, username, password);
    }

    /**
     * Tests that the database is reachable.
     *
     * @return {@code true} if a connection can be opened and validated
     */
    public boolean isReachable() {
        try (Connection c = getConnection()) {
            return c.isValid(5);
        } catch (SQLException e) {
            log.warn("Database reachability check failed: {}", e.getMessage());
            return false;
        }
    }

    public String getJdbcUrl()  { return jdbcUrl;  }
    public String getUsername() { return username; }

    /* ------------------------------------------------------------------ */
    /* Internal helpers                                                   */
    /* ------------------------------------------------------------------ */

    private static String requireProp(Properties props, String key) {
        String value = props.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Required property missing in database.properties: " + key);
        }
        return value.trim();
    }
}

