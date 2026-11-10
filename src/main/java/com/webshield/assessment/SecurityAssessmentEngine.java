package com.webshield.assessment;

import com.webshield.assessment.analyzers.*;
import com.webshield.assessment.models.AssessmentResult;
import com.webshield.config.DatabaseConfig;
import com.webshield.crawler.DiscoveredPage;
import com.webshield.http.HttpClientManager;
import com.webshield.http.HttpRequestBuilder;
import com.webshield.http.HttpRequestData;
import com.webshield.http.HttpResponseData;
import com.webshield.models.Website;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Orchestrates security assessments by running configured {@link AssessmentRule}
 * strategies against discovered pages and persisting findings to MySQL.
 */
@Component
public class SecurityAssessmentEngine {

    private static final Logger log = LoggerFactory.getLogger(SecurityAssessmentEngine.class);

    private final List<AssessmentRule> rules = new ArrayList<>();
    private final HttpClientManager httpManager;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    public interface AssessmentProgressListener {
        void onProgress(int pagesTested, int totalPages, int findingsCount, String currentUrl);
    }

    @Autowired
    public SecurityAssessmentEngine(HttpClientManager httpManager) {
        this.httpManager = httpManager;
        // Register default five assessment categories
        this.rules.add(new SecurityHeaderChecker());
        this.rules.add(new CookieSecurityChecker());
        this.rules.add(new InputReflectionAnalyzer());
        this.rules.add(new SqlErrorAnalyzer());
        this.rules.add(new InputValidationChecker());
    }

    public SecurityAssessmentEngine() {
        this((HttpClientManager) null);
    }

    public void configureRules(boolean checkHeaders, boolean checkCookies, boolean checkReflection,
                               boolean checkSqlErrors, boolean checkInputValidation) {
        rules.clear();
        if (checkHeaders) rules.add(new SecurityHeaderChecker());
        if (checkCookies) rules.add(new CookieSecurityChecker());
        if (checkReflection) rules.add(new InputReflectionAnalyzer());
        if (checkSqlErrors) rules.add(new SqlErrorAnalyzer());
        if (checkInputValidation) rules.add(new InputValidationChecker());
    }

    public void cancel() {
        cancelled.set(true);
    }

    public boolean isCancelled() {
        return cancelled.get();
    }

    /**
     * Executes the security assessment over discovered pages, collects findings,
     * and persists them to the database.
     */
    public List<AssessmentResult> runAssessment(long scanId, Website website,
                                               List<DiscoveredPage> pages,
                                               AssessmentProgressListener listener) {
        cancelled.set(false);
        List<AssessmentResult> allFindings = new ArrayList<>();
        if (pages == null || pages.isEmpty()) {
            log.warn("No discovered pages provided to assess for website: {}", website.getUrl());
            return allFindings;
        }

        HttpClientManager effectiveHttp = this.httpManager != null ? this.httpManager : new HttpClientManager();
        AssessmentContext context = new AssessmentContext(website, effectiveHttp, pages, cancelled);
        int total = pages.size();
        int tested = 0;

        for (DiscoveredPage page : pages) {
            if (cancelled.get()) {
                log.info("Assessment cancelled by user.");
                break;
            }

            tested++;
            if (listener != null) {
                listener.onProgress(tested, total, allFindings.size(), page.getUrl());
            }

            try {
                // Fetch page response
                HttpRequestData req = HttpRequestBuilder.get(page.getUrl()).timeout(15).build();
                HttpResponseData res = effectiveHttp.execute(req, website.getUrl());

                // Run each configured rule (passive analyze and active probe)
                for (AssessmentRule rule : rules) {
                    if (cancelled.get()) break;

                    try {
                        List<AssessmentResult> passive = rule.analyze(context, page, res);
                        for (AssessmentResult ar : passive) {
                            ar.setScanId(scanId);
                            ar.setPageId(page.getId());
                            allFindings.add(ar);
                        }

                        List<AssessmentResult> active = rule.probe(context, page);
                        for (AssessmentResult ar : active) {
                            ar.setScanId(scanId);
                            ar.setPageId(page.getId());
                            allFindings.add(ar);
                        }
                    } catch (Exception re) {
                        log.warn("Rule {} threw an exception on {}: {}", rule.getRuleId(), page.getUrl(), re.getMessage());
                    }
                }

                markPageTested(page.getId());

            } catch (Exception e) {
                log.warn("Failed to assess page {}: {}", page.getUrl(), e.getMessage());
            }
        }

        // Persist findings and update scan summary in MySQL
        persistFindings(scanId, allFindings);
        updateScanCompletion(scanId, tested, allFindings.size(), cancelled.get() ? "CANCELLED" : "COMPLETED");

        return allFindings;
    }

    private void markPageTested(long pageId) {
        if (pageId <= 0) return;
        String sql = "UPDATE discovered_pages SET was_tested = 1 WHERE id = ?";
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, pageId);
            ps.executeUpdate();
        } catch (SQLException ignored) {}
    }

    private void persistFindings(long scanId, List<AssessmentResult> findings) {
        if (scanId <= 0 || findings.isEmpty()) return;

        String insertSql = """
                INSERT INTO scan_findings
                (scan_id, vulnerability_id, page_id, severity, status, affected_url, affected_param,
                 http_method, finding_name, description, evidence, detection_method, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;

        try (Connection conn = DatabaseConfig.getInstance().getConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement ps = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                for (AssessmentResult f : findings) {
                    Integer vulnId = resolveVulnerabilityId(conn, f.getVulnerabilityCode());

                    ps.setLong(1, scanId);
                    if (vulnId != null) ps.setInt(2, vulnId); else ps.setNull(2, Types.INTEGER);
                    if (f.getPageId() != null && f.getPageId() > 0) ps.setLong(3, f.getPageId()); else ps.setNull(3, Types.BIGINT);

                    ps.setString(4, f.getSeverity().name());
                    ps.setString(5, f.getConfidence().name());
                    ps.setString(6, f.getAffectedUrl());
                    ps.setString(7, f.getAffectedParam());
                    ps.setString(8, f.getHttpMethod());
                    ps.setString(9, f.getFindingName());
                    ps.setString(10, f.getDescription());
                    ps.setString(11, f.getEvidence());
                    ps.setString(12, f.getDetectionMethod());
                    LocalDateTime det = f.getDetectedAt() != null ? f.getDetectedAt() : LocalDateTime.now();
                    ps.setTimestamp(13, Timestamp.valueOf(det));

                    ps.addBatch();
                }

                ps.executeBatch();
                conn.commit();
                log.info("Persisted {} findings for scan id={}", findings.size(), scanId);
            } catch (SQLException e) {
                conn.rollback();
                log.error("Failed to persist findings, rolled back", e);
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        } catch (SQLException e) {
            log.error("Database error persisting findings", e);
        }
    }

    private Integer resolveVulnerabilityId(Connection conn, String code) {
        if (code == null) return null;
        String sql = "SELECT id FROM vulnerabilities WHERE code = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, code);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        } catch (SQLException ignored) {}
        return null;
    }

    private void updateScanCompletion(long scanId, int pagesTested, int findingsCount, String status) {
        if (scanId <= 0) return;
        String sql = """
                UPDATE scans
                SET status = ?, completed_at = ?, pages_tested = ?, findings_count = ?
                WHERE id = ?
                """;
        try (Connection conn = DatabaseConfig.getInstance().getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, status);
            ps.setTimestamp(2, Timestamp.valueOf(LocalDateTime.now()));
            ps.setInt(3, pagesTested);
            ps.setInt(4, findingsCount);
            ps.setLong(5, scanId);
            ps.executeUpdate();
        } catch (SQLException e) {
            log.error("Failed to update scan status", e);
        }
    }
}

