package com.webshield.crawler;

import com.webshield.auth.SessionManager;
import com.webshield.config.DatabaseConfig;
import com.webshield.models.User;
import com.webshield.models.Website;
import com.webshield.website.WebsiteRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Coordinates web crawling tasks and persists discovered pages, forms, and inputs into MySQL.
 */
@Component
public class CrawlManager {

    private static final Logger log = LoggerFactory.getLogger(CrawlManager.class);

    private final WebCrawler crawler;
    private final WebsiteRepository websiteRepository;

    public CrawlManager() {
        this(com.webshield.config.SpringContext.getBean(WebCrawler.class) != null
                ? com.webshield.config.SpringContext.getBean(WebCrawler.class) : new WebCrawler(),
             com.webshield.config.SpringContext.getBean(WebsiteRepository.class) != null
                ? com.webshield.config.SpringContext.getBean(WebsiteRepository.class) : new WebsiteRepository());
    }

    public CrawlManager(WebCrawler crawler, WebsiteRepository websiteRepository) {
        this.crawler = crawler;
        this.websiteRepository = websiteRepository;
    }

    public void cancelCurrentCrawl() {
        crawler.cancel();
    }

    public void cancel() {
        cancelCurrentCrawl();
    }

    /**
     * Executes crawling for the authorized website and saves all discoveries into the database.
     */
    public CrawlResult crawlAndPersist(long websiteId, CrawlConfiguration config, WebCrawler.CrawlProgressListener listener) {
        User user = SessionManager.getInstance().getCurrentUser();
        if (user == null) {
            throw new IllegalStateException("Authentication required to crawl website.");
        }

        Optional<Website> websiteOpt = websiteRepository.findById(websiteId, user.getId());
        if (websiteOpt.isEmpty()) {
            throw new IllegalArgumentException("Website not found or not owned by the current user.");
        }

        Website website = websiteOpt.get();
        if (!website.isAuthorized()) {
            throw new IllegalStateException("Website is not confirmed as authorized for assessment.");
        }

        long scanId = createScanRecord(website.getId(), user.getId(), config);

        // Execute crawl
        CrawlResult result = crawler.crawl(config, listener);

        // Save discoveries to MySQL
        saveCrawlDiscoveries(scanId, website.getId(), result);

        // Update scan & website records
        updateScanRecord(scanId, result);
        updateWebsiteLastScan(website.getId());

        return result;
    }

    private long createScanRecord(long websiteId, int userId, CrawlConfiguration config) {
        String sql = """
                INSERT INTO scans (website_id, user_id, status, crawl_depth, max_pages, timeout_seconds, started_at, created_at)
                VALUES (?, ?, 'CRAWLING', ?, ?, ?, ?, ?)
                """;
        LocalDateTime now = LocalDateTime.now();
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            ps.setLong(1, websiteId);
            ps.setInt(2, userId);
            ps.setInt(3, config.getMaxDepth());
            ps.setInt(4, config.getMaxPages());
            ps.setInt(5, config.getRequestTimeoutSeconds());
            ps.setTimestamp(6, Timestamp.valueOf(now));
            ps.setTimestamp(7, Timestamp.valueOf(now));

            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            }
        } catch (SQLException e) {
            log.error("Failed to create scan record", e);
        }
        return 0;
    }

    private void saveCrawlDiscoveries(long scanId, long websiteId, CrawlResult result) {
        String insertPageSql = """
                INSERT INTO discovered_pages (scan_id, website_id, url, page_title, http_method, status_code, content_type, depth, has_forms, was_tested, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;

        String insertFormSql = """
                INSERT INTO forms (page_id, scan_id, form_action, form_method, form_id, form_name, field_count, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """;

        String insertFieldSql = """
                INSERT INTO input_fields (form_id, field_name, field_type, field_id, placeholder, is_required, has_maxlength, has_pattern, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;

        try (Connection conn = DatabaseConfig.getInstance().getConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement pageStmt = conn.prepareStatement(insertPageSql, Statement.RETURN_GENERATED_KEYS);
                 PreparedStatement formStmt = conn.prepareStatement(insertFormSql, Statement.RETURN_GENERATED_KEYS);
                 PreparedStatement fieldStmt = conn.prepareStatement(insertFieldSql)) {

                for (DiscoveredPage page : result.getPages()) {
                    page.setScanId(scanId);
                    page.setWebsiteId(websiteId);

                    pageStmt.setLong(1, scanId);
                    pageStmt.setLong(2, websiteId);
                    pageStmt.setString(3, page.getUrl());
                    pageStmt.setString(4, page.getPageTitle());
                    pageStmt.setString(5, page.getHttpMethod());
                    pageStmt.setInt(6, page.getStatusCode());
                    pageStmt.setString(7, page.getContentType());
                    pageStmt.setInt(8, page.getDepth());
                    pageStmt.setBoolean(9, page.isHasForms());
                    pageStmt.setBoolean(10, page.isWasTested());
                    pageStmt.setTimestamp(11, Timestamp.valueOf(page.getDiscoveredAt()));

                    pageStmt.executeUpdate();

                    long pageId = 0;
                    try (ResultSet rs = pageStmt.getGeneratedKeys()) {
                        if (rs.next()) {
                            pageId = rs.getLong(1);
                            page.setId(pageId);
                        }
                    }

                    if (pageId > 0 && page.isHasForms()) {
                        for (DiscoveredForm form : page.getForms()) {
                            form.setPageId(pageId);

                            formStmt.setLong(1, pageId);
                            formStmt.setLong(2, scanId);
                            formStmt.setString(3, form.getFormAction());
                            formStmt.setString(4, form.getFormMethod());
                            formStmt.setString(5, form.getFormId());
                            formStmt.setString(6, form.getFormName());
                            formStmt.setInt(7, form.getFieldCount());
                            formStmt.setTimestamp(8, Timestamp.valueOf(LocalDateTime.now()));

                            formStmt.executeUpdate();

                            long formId = 0;
                            try (ResultSet rsForm = formStmt.getGeneratedKeys()) {
                                if (rsForm.next()) {
                                    formId = rsForm.getLong(1);
                                    form.setId(formId);
                                }
                            }

                            if (formId > 0) {
                                for (DiscoveredField field : form.getFields()) {
                                    field.setFormId(formId);

                                    fieldStmt.setLong(1, formId);
                                    fieldStmt.setString(2, field.getName());
                                    fieldStmt.setString(3, field.getType());
                                    fieldStmt.setString(4, field.getFieldId());
                                    fieldStmt.setString(5, field.getPlaceholder());
                                    fieldStmt.setBoolean(6, field.isRequired());
                                    fieldStmt.setBoolean(7, field.isHasMaxlength());
                                    fieldStmt.setBoolean(8, field.isHasPattern());
                                    fieldStmt.setTimestamp(9, Timestamp.valueOf(LocalDateTime.now()));

                                    fieldStmt.addBatch();
                                }
                                fieldStmt.executeBatch();
                            }
                        }
                    }
                }

                conn.commit();
                log.info("Persisted {} discovered pages for scan id={}", result.getPages().size(), scanId);
            } catch (SQLException e) {
                conn.rollback();
                log.error("Failed to persist crawl discoveries, transaction rolled back", e);
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        } catch (SQLException e) {
            log.error("Database error during crawl persistence", e);
        }
    }

    private void updateScanRecord(long scanId, CrawlResult result) {
        if (scanId <= 0) return;
        String sql = """
                UPDATE scans
                SET status = ?, completed_at = ?, pages_discovered = ?, pages_tested = 0
                WHERE id = ?
                """;
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, result.getStatus());
            ps.setTimestamp(2, Timestamp.valueOf(LocalDateTime.now()));
            ps.setInt(3, result.getTotalPages());
            ps.setLong(4, scanId);
            ps.executeUpdate();
        } catch (SQLException e) {
            log.error("Failed to update scan id={}", scanId, e);
        }
    }

    private void updateWebsiteLastScan(long websiteId) {
        String sql = "UPDATE websites SET last_scan_at = ? WHERE id = ?";
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
            ps.setLong(2, websiteId);
            ps.executeUpdate();
        } catch (SQLException e) {
            log.error("Failed to update website last_scan_at id={}", websiteId, e);
        }
    }

    /**
     * Loads all discovered pages (and nested forms & fields) for a given website.
     */
    public List<DiscoveredPage> getDiscoveredPages(long websiteId) {
        List<DiscoveredPage> pages = new ArrayList<>();
        String pageSql = "SELECT * FROM discovered_pages WHERE website_id = ? ORDER BY depth ASC, id ASC";
        String formSql = "SELECT * FROM forms WHERE page_id = ?";
        String fieldSql = "SELECT * FROM input_fields WHERE form_id = ?";

        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement psPage = conn.prepareStatement(pageSql)) {

            psPage.setLong(1, websiteId);
            try (ResultSet rs = psPage.executeQuery()) {
                while (rs.next()) {
                    DiscoveredPage page = new DiscoveredPage(rs.getString("url"), rs.getInt("depth"));
                    page.setId(rs.getLong("id"));
                    page.setScanId(rs.getLong("scan_id"));
                    page.setWebsiteId(rs.getLong("website_id"));
                    page.setPageTitle(rs.getString("page_title"));
                    page.setHttpMethod(rs.getString("http_method"));
                    page.setStatusCode(rs.getInt("status_code"));
                    page.setContentType(rs.getString("content_type"));
                    page.setHasForms(rs.getBoolean("has_forms"));
                    page.setWasTested(rs.getBoolean("was_tested"));

                    Timestamp ts = rs.getTimestamp("discovered_at");
                    if (ts != null) page.setDiscoveredAt(ts.toLocalDateTime());

                    // Load forms if any
                    if (page.isHasForms()) {
                        try (PreparedStatement psForm = conn.prepareStatement(formSql)) {
                            psForm.setLong(1, page.getId());
                            try (ResultSet rsForm = psForm.executeQuery()) {
                                while (rsForm.next()) {
                                    DiscoveredForm form = new DiscoveredForm(
                                            rsForm.getString("form_action"),
                                            rsForm.getString("form_method"),
                                            rsForm.getString("form_id"),
                                            rsForm.getString("form_name")
                                    );
                                    form.setId(rsForm.getLong("id"));
                                    form.setPageId(page.getId());

                                    // Load fields
                                    try (PreparedStatement psField = conn.prepareStatement(fieldSql)) {
                                        psField.setLong(1, form.getId());
                                        try (ResultSet rsField = psField.executeQuery()) {
                                            while (rsField.next()) {
                                                DiscoveredField field = new DiscoveredField(
                                                        rsField.getString("field_name"),
                                                        rsField.getString("field_type"),
                                                        rsField.getString("field_id"),
                                                        rsField.getString("placeholder"),
                                                        rsField.getBoolean("is_required"),
                                                        rsField.getBoolean("has_maxlength"),
                                                        rsField.getBoolean("has_pattern")
                                                );
                                                field.setId(rsField.getLong("id"));
                                                field.setFormId(form.getId());
                                                form.addField(field);
                                            }
                                        }
                                    }

                                    page.addForm(form);
                                }
                            }
                        }
                    }

                    pages.add(page);
                }
            }
        } catch (SQLException e) {
            log.error("Failed to query discovered pages for website id: {}", websiteId, e);
        }
        return pages;
    }
}

