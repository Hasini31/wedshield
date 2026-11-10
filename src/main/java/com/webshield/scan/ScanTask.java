package com.webshield.scan;

import com.webshield.assessment.SecurityAssessmentEngine;
import com.webshield.assessment.models.AssessmentResult;
import com.webshield.crawler.CrawlConfiguration;
import com.webshield.crawler.CrawlManager;
import com.webshield.crawler.CrawlResult;
import com.webshield.crawler.DiscoveredPage;
import com.webshield.database.repositories.FindingRepository;
import com.webshield.database.repositories.ScanRepository;
import com.webshield.findings.FindingDeduplicator;
import com.webshield.models.SecurityFinding;
import com.webshield.models.Website;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * Executes a full automated security scan lifecycle in the background.
 * Coordinates crawl discovery, vulnerability rule execution, deduplication, and persistence.
 */
public class ScanTask implements Callable<ScanExecutionResult> {

    private static final Logger log = LoggerFactory.getLogger(ScanTask.class);

    private final ScanConfiguration config;
    private final ScanProgressTracker tracker;
    private final CrawlManager crawlManager;
    private final SecurityAssessmentEngine engine;
    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;

    private volatile boolean cancelled = false;
    private volatile long scanId = 0;
    private final LocalDateTime startedAt = LocalDateTime.now();

    public ScanTask(ScanConfiguration config, ScanProgressTracker tracker) {
        this(config, tracker,
                com.webshield.config.SpringContext.getBean(CrawlManager.class) != null
                        ? com.webshield.config.SpringContext.getBean(CrawlManager.class) : new CrawlManager(),
                com.webshield.config.SpringContext.getBean(SecurityAssessmentEngine.class) != null
                        ? com.webshield.config.SpringContext.getBean(SecurityAssessmentEngine.class) : new SecurityAssessmentEngine(),
                com.webshield.config.SpringContext.getBean(ScanRepository.class) != null
                        ? com.webshield.config.SpringContext.getBean(ScanRepository.class) : new ScanRepository(),
                com.webshield.config.SpringContext.getBean(FindingRepository.class) != null
                        ? com.webshield.config.SpringContext.getBean(FindingRepository.class) : new FindingRepository());
    }

    public ScanTask(ScanConfiguration config, ScanProgressTracker tracker,
                    CrawlManager crawlManager, SecurityAssessmentEngine engine,
                    ScanRepository scanRepository, FindingRepository findingRepository) {
        this.config = config;
        this.tracker = tracker != null ? tracker : new ScanProgressTracker();
        this.crawlManager = crawlManager;
        this.engine = engine;
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
    }

    @Override
    public ScanExecutionResult call() {
        try {
            config.validate();
            tracker.start();

            // 1. Initialize scan record
            tracker.setStatus(ScanStatus.INITIALIZING);
            tracker.setOperation("Registering scan record in database...");
            scanId = scanRepository.createScan(
                    config.getWebsiteId(),
                    config.getUserId(),
                    config.getCrawlDepth(),
                    config.getMaxPages(),
                    config.getTimeoutSeconds(),
                    config.isCheckHeaders(),
                    config.isCheckCookies(),
                    config.isCheckReflection(),
                    config.isCheckSqlErrors(),
                    config.isCheckInputValidation()
            );

            if (checkCancelled()) {
                return handleCancellation();
            }

            // 2. Discover Endpoints (Crawl)
            tracker.setStatus(ScanStatus.CRAWLING);
            tracker.setOperation("Inspecting endpoint structure for " + config.getWebsiteUrl());

            List<DiscoveredPage> pages = crawlManager.getDiscoveredPages(config.getWebsiteId());
            if (pages.isEmpty()) {
                tracker.setOperation("Starting automated crawler on " + config.getWebsiteUrl());
                CrawlConfiguration crawlConfig = new CrawlConfiguration(config.getWebsiteUrl())
                        .setMaxDepth(config.getCrawlDepth())
                        .setMaxPages(config.getMaxPages())
                        .setRequestTimeoutSeconds(config.getTimeoutSeconds())
                        .setAllowLocalhost(true);

                crawlManager.crawlAndPersist(config.getWebsiteId(), crawlConfig, (count, forms, url) -> {
                    if (cancelled) return;
                    tracker.setPagesDiscovered(count);
                    tracker.setOperation("Crawling: " + url);
                });

                pages = crawlManager.getDiscoveredPages(config.getWebsiteId());
            }

            if (config.getMaxPages() > 0 && pages.size() > config.getMaxPages()) {
                pages = new ArrayList<>(pages.subList(0, config.getMaxPages()));
            }

            tracker.setPagesDiscovered(pages.size());

            if (checkCancelled()) {
                return handleCancellation();
            }

            if (pages.isEmpty()) {
                log.warn("No pages discovered for scan id={}. Finalizing.", scanId);
                scanRepository.completeScan(scanId, "COMPLETED", 0, 0, 0, "No pages discovered");
                tracker.setStatus(ScanStatus.COMPLETED);
                tracker.setOperation("Target unreachable or timed out (0 pages discovered).");
                return ScanExecutionResult.completed(scanId, config.getWebsiteId(), config.getWebsiteName(),
                        0, 0, Collections.emptyList(), startedAt, LocalDateTime.now());
            }

            // 3. Security Assessment
            tracker.setStatus(ScanStatus.ASSESSING);
            tracker.setOperation("Configuring security rules...");
            engine.configureRules(
                    config.isCheckHeaders(),
                    config.isCheckCookies(),
                    config.isCheckReflection(),
                    config.isCheckSqlErrors(),
                    config.isCheckInputValidation()
            );

            Website websiteModel = new Website(config.getWebsiteName(), config.getWebsiteUrl());
            websiteModel.setId(config.getWebsiteId());

            List<AssessmentResult> rawResults = engine.runAssessment(
                    scanId, websiteModel, pages,
                    (tested, total, findings, currentUrl) -> {
                        if (cancelled) return;
                        tracker.setPagesTested(tested);
                        tracker.incrementChecksCompleted(5);
                        tracker.setFindingsGenerated(findings);
                        tracker.setOperation("Auditing: " + currentUrl);

                        if (config.getRateLimitDelayMs() > 0) {
                            try {
                                Thread.sleep(config.getRateLimitDelayMs());
                            } catch (InterruptedException ignored) {
                                Thread.currentThread().interrupt();
                            }
                        }
                    }
            );

            if (checkCancelled()) {
                return handleCancellation();
            }

            // 4. Deduplicate and Classify Findings
            tracker.setStatus(ScanStatus.SAVING_RESULTS);
            tracker.setOperation("Deduplicating and classifying security findings...");

            List<AssessmentResult> deduplicatedResults = FindingDeduplicator.deduplicateResults(
                    config.getWebsiteId(), rawResults);

            List<SecurityFinding> securityFindings = new ArrayList<>();
            for (AssessmentResult ar : deduplicatedResults) {
                securityFindings.add(SecurityFinding.fromAssessmentResult(
                        ar, config.getWebsiteId(), config.getWebsiteName()));
            }

            // 5. Persist Findings to Database
            tracker.setOperation("Saving " + securityFindings.size() + " findings to database...");
            findingRepository.insertFindingsBatch(scanId, securityFindings);

            // 6. Complete Scan
            tracker.setFindingsGenerated(securityFindings.size());
            scanRepository.completeScan(scanId, "COMPLETED", pages.size(), pages.size(),
                    securityFindings.size(), null);

            tracker.setStatus(ScanStatus.COMPLETED);
            tracker.setOperation("Security assessment finished successfully.");

            log.info("Scan id={} completed with {} unique findings across {} pages.",
                    scanId, securityFindings.size(), pages.size());

            return ScanExecutionResult.completed(
                    scanId, config.getWebsiteId(), config.getWebsiteName(),
                    pages.size(), pages.size(), securityFindings, startedAt, LocalDateTime.now()
            );

        } catch (Exception e) {
            log.error("Scan execution failed for target {}", config.getWebsiteUrl(), e);
            if (scanId > 0) {
                scanRepository.completeScan(scanId, "FAILED", tracker.getPagesDiscovered(),
                        tracker.getPagesTested(), tracker.getFindingsGenerated(), e.getMessage());
            }
            tracker.setStatus(ScanStatus.FAILED);
            tracker.setOperation("Assessment failed: " + e.getMessage());
            return ScanExecutionResult.failed(scanId, config.getWebsiteId(), config.getWebsiteName(),
                    e.getMessage(), startedAt);
        }
    }

    /**
     * Cooperatively cancels the running scan task.
     */
    public void cancel() {
        this.cancelled = true;
        if (engine != null) {
            engine.cancel();
        }
        if (crawlManager != null) {
            crawlManager.cancel();
        }
    }

    public boolean isCancelled() {
        return cancelled;
    }

    public long getScanId() {
        return scanId;
    }

    public ScanConfiguration getConfig() {
        return config;
    }

    public ScanProgressTracker getTracker() {
        return tracker;
    }

    private boolean checkCancelled() {
        return cancelled || Thread.currentThread().isInterrupted();
    }

    private ScanExecutionResult handleCancellation() {
        log.info("Cooperative cancellation processed for scan id={}", scanId);
        if (scanId > 0) {
            scanRepository.updateScanStatus(scanId, "CANCELLED");
        }
        tracker.setStatus(ScanStatus.CANCELLED);
        tracker.setOperation("Scan cancelled by operator.");
        return ScanExecutionResult.cancelled(scanId, config.getWebsiteId(), config.getWebsiteName(),
                tracker.getPagesDiscovered(), tracker.getPagesTested(), startedAt);
    }
}

