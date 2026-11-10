package com.webshield.website;

import com.webshield.auth.SessionManager;
import com.webshield.config.DatabaseConfig;
import com.webshield.models.User;
import com.webshield.models.Website;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Service managing website targets. Keeps all business logic outside UI controllers.
 */
@Service
public class WebsiteService {

    private static final Logger log = LoggerFactory.getLogger(WebsiteService.class);

    private final WebsiteRepository repository;
    private final WebsiteValidator validator;

    public WebsiteService() {
        this(com.webshield.config.SpringContext.getBean(WebsiteRepository.class) != null
                ? com.webshield.config.SpringContext.getBean(WebsiteRepository.class) : new WebsiteRepository(),
             com.webshield.config.SpringContext.getBean(WebsiteValidator.class) != null
                ? com.webshield.config.SpringContext.getBean(WebsiteValidator.class) : new WebsiteValidator());
    }

    public WebsiteService(WebsiteRepository repository, WebsiteValidator validator) {
        this.repository = repository;
        this.validator = validator;
    }

    private int getAuthenticatedUserId() {
        User user = SessionManager.getInstance().getCurrentUser();
        if (user == null) {
            throw new IllegalStateException("User must be authenticated to perform website operations.");
        }
        return user.getId();
    }

    public Website registerWebsite(String name, String rawUrl, String description, boolean authorized) {
        int userId = getAuthenticatedUserId();
        validator.validate(name, rawUrl, authorized);
        String normalizedUrl = validator.normalizeWebsiteUrl(rawUrl);

        if (repository.existsByUrlAndUserId(normalizedUrl, userId, null)) {
            throw new IllegalArgumentException("A website with this URL is already registered under your account.");
        }

        Website website = new Website();
        website.setUserId(userId);
        website.setName(name.trim());
        website.setUrl(normalizedUrl);
        website.setDescription(description != null ? description.trim() : null);
        website.setAuthorized(authorized);
        website.setStatus("ACTIVE");

        Website saved = repository.save(website);
        log.info("Registered new authorized website id={} for user={}: {}", saved.getId(), userId, saved.getUrl());
        return saved;
    }

    public boolean updateWebsite(long websiteId, String name, String rawUrl, String description,
                                 boolean authorized, String status) {
        int userId = getAuthenticatedUserId();
        validator.validate(name, rawUrl, authorized);
        String normalizedUrl = validator.normalizeWebsiteUrl(rawUrl);

        if (repository.existsByUrlAndUserId(normalizedUrl, userId, websiteId)) {
            throw new IllegalArgumentException("Another registered website already uses this URL.");
        }

        Optional<Website> existing = repository.findById(websiteId, userId);
        if (existing.isEmpty()) {
            throw new IllegalArgumentException("Website not found or not owned by the current user.");
        }

        Website w = existing.get();
        w.setName(name.trim());
        w.setUrl(normalizedUrl);
        w.setDescription(description != null ? description.trim() : null);
        w.setAuthorized(authorized);
        if (status != null && !status.isBlank()) {
            w.setStatus(status.trim().toUpperCase());
        }

        boolean ok = repository.update(w);
        log.info("Updated website id={}: {}", websiteId, w.getUrl());
        return ok;
    }

    public boolean deleteWebsite(long websiteId) {
        int userId = getAuthenticatedUserId();
        boolean deleted = repository.delete(websiteId, userId);
        if (deleted) {
            log.info("Deleted website id={} for user={}", websiteId, userId);
        }
        return deleted;
    }

    public Optional<Website> getWebsite(long websiteId) {
        int userId = getAuthenticatedUserId();
        return repository.findById(websiteId, userId);
    }

    public List<Website> getUserWebsites() {
        User user = SessionManager.getInstance().getCurrentUser();
        if (user == null) {
            return Collections.emptyList();
        }
        return repository.findAllByUserId(user.getId());
    }

    /**
     * Loads a complete summary for the website including count of discovered pages,
     * forms, input fields, and findings.
     */
    public Optional<WebsiteSummary> getWebsiteSummary(long websiteId) {
        int userId = getAuthenticatedUserId();
        Optional<Website> websiteOpt = repository.findById(websiteId, userId);
        if (websiteOpt.isEmpty()) {
            return Optional.empty();
        }
        Website w = websiteOpt.get();

        int pages = 0;
        int forms = 0;
        int inputs = 0;
        int findings = 0;
        String scanStatus = "NOT_SCANNED";

        String pagesSql = "SELECT COUNT(*) FROM discovered_pages WHERE website_id = ?";
        String formsSql = "SELECT COUNT(*) FROM forms f JOIN discovered_pages dp ON f.page_id = dp.id WHERE dp.website_id = ?";
        String inputsSql = "SELECT COUNT(*) FROM input_fields i JOIN forms f ON i.form_id = f.id JOIN discovered_pages dp ON f.page_id = dp.id WHERE dp.website_id = ?";
        String scanSql = "SELECT status, findings_count FROM scans WHERE website_id = ? ORDER BY created_at DESC LIMIT 1";

        try (Connection conn = DatabaseConfig.getInstance().getConnection()) {
            try (PreparedStatement ps = conn.prepareStatement(pagesSql)) {
                ps.setLong(1, websiteId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) pages = rs.getInt(1);
                }
            }
            try (PreparedStatement ps = conn.prepareStatement(formsSql)) {
                ps.setLong(1, websiteId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) forms = rs.getInt(1);
                }
            }
            try (PreparedStatement ps = conn.prepareStatement(inputsSql)) {
                ps.setLong(1, websiteId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) inputs = rs.getInt(1);
                }
            }
            try (PreparedStatement ps = conn.prepareStatement(scanSql)) {
                ps.setLong(1, websiteId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        scanStatus = rs.getString("status");
                        findings = rs.getInt("findings_count");
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Failed to load website summary for website id: {}", websiteId, e);
        }

        WebsiteSummary summary = new WebsiteSummary(
                w.getId(),
                w.getName(),
                w.getUrl(),
                w.getDescription(),
                w.isAuthorized(),
                w.getStatus(),
                w.getCreatedAt(),
                w.getLastScanAt(),
                pages,
                forms,
                inputs,
                findings,
                scanStatus
        );

        return Optional.of(summary);
    }
}

