package com.webshield.website.reporting;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webshield.api.analysis.RedactionUtils;
import com.webshield.api.llm.GeminiLlmProvider;
import com.webshield.api.llm.LlmConfiguration;
import com.webshield.api.llm.LlmException;
import com.webshield.api.llm.LlmService;
import com.webshield.assessment.models.Severity;
import com.webshield.config.SpringContext;
import com.webshield.database.repositories.FindingRepository;
import com.webshield.database.repositories.ScanRecord;
import com.webshield.database.repositories.ScanRepository;
import com.webshield.models.FindingEvidence;
import com.webshield.models.SecurityFinding;
import com.webshield.models.Website;
import com.webshield.website.WebsiteRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Service orchestrating website-specific AI security report generation powered by Google Gemini.
 * Pulls scan metadata, targets, and verified findings for a single designated scan run,
 * redacts sensitive tokens, and prompts Gemini to format a publication-grade 10-section security report.
 */
@Service
public class WebsiteAiReportService {

    private static final Logger log = LoggerFactory.getLogger(WebsiteAiReportService.class);
    private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm:ss");

    private final ScanRepository scanRepository;
    private final WebsiteRepository websiteRepository;
    private final FindingRepository findingRepository;
    private final LlmService llmService;
    private final ObjectMapper objectMapper;

    public WebsiteAiReportService() {
        this(
                SpringContext.getBean(ScanRepository.class) != null ? SpringContext.getBean(ScanRepository.class) : new ScanRepository(),
                SpringContext.getBean(WebsiteRepository.class) != null ? SpringContext.getBean(WebsiteRepository.class) : new WebsiteRepository(),
                SpringContext.getBean(FindingRepository.class) != null ? SpringContext.getBean(FindingRepository.class) : new FindingRepository(),
                SpringContext.getBean(LlmService.class) != null ? SpringContext.getBean(LlmService.class) : new LlmService()
        );
    }

    public WebsiteAiReportService(ScanRepository scanRepository,
                                  WebsiteRepository websiteRepository,
                                  FindingRepository findingRepository,
                                  LlmService llmService) {
        this.scanRepository = scanRepository;
        this.websiteRepository = websiteRepository;
        this.findingRepository = findingRepository;
        this.llmService = llmService;
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Generates a complete AI security report for a single specific website scan.
     *
     * @param scanId ID of the completed website scan
     * @return Generated WebsiteReportResult containing report text and scan metadata
     * @throws LlmException if Gemini fails, API key is missing, or network fails
     */
    public WebsiteReportResult generateWebsiteAiReport(long scanId) throws LlmException {
        log.info("Starting Website AI Security Report generation for Scan #{}", scanId);

        // 1. Retrieve Scan record
        ScanRecord scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new IllegalArgumentException("Scan #" + scanId + " not found in database."));

        // 2. Retrieve Website target information
        Website website = websiteRepository.findById(scan.getWebsiteId())
                .orElseGet(() -> {
                    Website fallback = new Website();
                    fallback.setId(scan.getWebsiteId());
                    fallback.setName(scan.getWebsiteName() != null ? scan.getWebsiteName() : "Target Website #" + scan.getWebsiteId());
                    fallback.setUrl("https://" + (scan.getWebsiteName() != null ? scan.getWebsiteName() : "unknown-target"));
                    return fallback;
                });

        // 3. Retrieve findings strictly for this scan (isolated)
        List<SecurityFinding> findings = findingRepository.findSecurityFindingsByScanId(scanId);
        log.info("Retrieved {} findings belonging strictly to Scan #{} (Website: {})", findings.size(), scanId, website.getName());

        // 4. Calculate severity breakdown
        Map<String, Long> severityCounts = new LinkedHashMap<>();
        severityCounts.put("CRITICAL", 0L);
        severityCounts.put("HIGH", 0L);
        severityCounts.put("MEDIUM", 0L);
        severityCounts.put("LOW", 0L);
        severityCounts.put("INFORMATIONAL", 0L);

        for (SecurityFinding f : findings) {
            String sev = f.getSeverity() != null ? f.getSeverity().name() : "INFORMATIONAL";
            severityCounts.put(sev, severityCounts.getOrDefault(sev, 0L) + 1);
        }

        // 5. Build structured scan telemetry JSON (sanitized & redacted)
        String scanTelemetryJson = buildScanTelemetryPayload(scan, website, findings, severityCounts);

        // 6. Build the System Instruction enforcing the 10 mandatory sections
        String systemInstruction = buildSystemPrompt();

        // 7. Execute call to Google Gemini
        LlmConfiguration config = llmService.getConfiguration();
        GeminiLlmProvider gemini = llmService.getGeminiProvider();

        String reportMarkdown = gemini.generateCompleteReport(systemInstruction, scanTelemetryJson, config);

        LocalDateTime now = LocalDateTime.now();
        return new WebsiteReportResult(
                scanId,
                website,
                scan,
                findings,
                severityCounts,
                reportMarkdown,
                now,
                config.modelName()
        );
    }

    private String buildScanTelemetryPayload(ScanRecord scan, Website website, List<SecurityFinding> findings, Map<String, Long> severityCounts) {
        Map<String, Object> payload = new LinkedHashMap<>();

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("scanId", scan.getId());
        meta.put("websiteName", website.getName());
        meta.put("websiteUrl", website.getUrl());
        meta.put("websiteDescription", website.getDescription() != null ? website.getDescription() : "Not available in scan data.");
        meta.put("scanStatus", scan.getStatus());
        meta.put("startedAt", scan.getStartedAt() != null ? scan.getStartedAt().format(DATE_FMT) : "Not available in scan data.");
        meta.put("completedAt", scan.getCompletedAt() != null ? scan.getCompletedAt().format(DATE_FMT) : "Not available in scan data.");
        meta.put("duration", formatDuration(scan));
        meta.put("pagesDiscovered", scan.getPagesDiscovered());
        meta.put("pagesTested", scan.getPagesTested());
        meta.put("crawlDepth", scan.getCrawlDepth());
        meta.put("maxPagesLimit", scan.getMaxPages());
        meta.put("timeoutSeconds", scan.getTimeoutSeconds());
        payload.put("metadata", meta);

        payload.put("severitySummary", severityCounts);
        payload.put("totalFindings", findings.size());

        // Executed Testing Categories & Mechanisms
        List<Map<String, String>> tests = List.of(
                Map.of("category", "Security Headers", "test", "Strict-Transport-Security (HSTS)", "status", "EXECUTED", "mechanism", "Response header presence & max-age evaluation"),
                Map.of("category", "Security Headers", "test", "Content-Security-Policy (CSP)", "status", "EXECUTED", "mechanism", "Directive presence & script-src safety check"),
                Map.of("category", "Security Headers", "test", "X-Frame-Options", "status", "EXECUTED", "mechanism", "DENY/SAMEORIGIN clickjacking protection check"),
                Map.of("category", "Security Headers", "test", "X-Content-Type-Options", "status", "EXECUTED", "mechanism", "nosniff MIME-type sniffing defense check"),
                Map.of("category", "Security Headers", "test", "Referrer-Policy", "status", "EXECUTED", "mechanism", "Strict-origin referrer leak protection check"),
                Map.of("category", "Cookie Security", "test", "HttpOnly Session Flags", "status", "EXECUTED", "mechanism", "Set-Cookie attribute inspection preventing XSS theft"),
                Map.of("category", "Cookie Security", "test", "Secure Cookie Flags", "status", "EXECUTED", "mechanism", "Set-Cookie HTTPS-only transmission inspection"),
                Map.of("category", "Cookie Security", "test", "SameSite Attribute", "status", "EXECUTED", "mechanism", "Strict/Lax CSRF protection attribute validation"),
                Map.of("category", "Web Security", "test", "Reflected Input Probe Reflection", "status", "EXECUTED", "mechanism", "Non-destructive parameter probe reflection analysis"),
                Map.of("category", "Database Security", "test", "SQL Injection Error Signatures", "status", "EXECUTED", "mechanism", "Benign syntax probes checking database error reflection")
        );
        payload.put("executedTests", tests);

        // Sanitize & redact individual findings
        List<Map<String, Object>> findingList = new ArrayList<>();
        for (SecurityFinding f : findings) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("findingId", f.getId());
            item.put("vulnerabilityCode", f.getVulnerabilityCode() != null ? f.getVulnerabilityCode() : "WS-GEN-000");
            item.put("findingName", f.getFindingName() != null ? f.getFindingName() : "Unnamed Security Finding");
            item.put("severity", f.getSeverity() != null ? f.getSeverity().name() : "INFORMATIONAL");
            item.put("confidence", f.getConfidenceLevel() != null ? f.getConfidenceLevel().name() : "POTENTIAL");
            item.put("category", f.getCategory() != null ? f.getCategory() : "Web Security");
            item.put("affectedUrl", RedactionUtils.redactSensitiveData(f.getAffectedUrl() != null ? f.getAffectedUrl() : "Not available in scan data."));
            item.put("affectedParam", RedactionUtils.redactSensitiveData(f.getAffectedParam() != null ? f.getAffectedParam() : "Not parameter-specific"));
            item.put("httpMethod", f.getHttpMethod() != null ? f.getHttpMethod() : "GET");
            item.put("description", f.getDescription() != null ? f.getDescription() : "Not available in scan data.");
            item.put("securityImpact", f.getRemediation() != null ? f.getRemediation() : "Not available in scan data.");

            // Redact evidence
            FindingEvidence ev = f.getEvidence();
            if (ev != null) {
                Map<String, String> evMap = new LinkedHashMap<>();
                if (ev.getDescription() != null) evMap.put("note", RedactionUtils.redactSensitiveData(ev.getDescription()));
                if (ev.getRequestHeaders() != null) evMap.put("requestHeaders", RedactionUtils.redactSensitiveData(ev.getRequestHeaders()));
                if (ev.getResponseHeaders() != null) evMap.put("responseHeaders", RedactionUtils.redactSensitiveData(ev.getResponseHeaders()));
                if (ev.getResponseExcerpt() != null) evMap.put("responseExcerpt", RedactionUtils.redactSensitiveData(ev.getResponseExcerpt()));
                item.put("evidence", evMap);
            } else {
                item.put("evidence", "Not available in scan data.");
            }

            findingList.add(item);
        }
        payload.put("findings", findingList);

        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(payload);
        } catch (Exception e) {
            return payload.toString();
        }
    }

    private String buildSystemPrompt() {
        return """
                You are a Senior Principal Cybersecurity Assessment Expert generating an official, professional vulnerability assessment report for WebShield.
                You are analyzing REAL scan results from a single specific website security scan.
                
                MANDATORY RULES & CONSTRAINTS:
                1. STRICT PROFESSIONAL FORMAT: You must format the response as a formal, publication-grade cybersecurity document.
                2. NO INVENTED DATA: Use only the provided real scan findings, URLs, and telemetry. If any technical detail is absent, write exactly "Not available in scan data."
                3. NO INVENTED SCORES: Do not invent a numeric score or percentage score unless provided.
                4. NEVER CLAIM 100% SECURE: Never state that the target is completely secure or immune to vulnerabilities.
                5. COVER ONLY THIS SELECTED SCAN: Do not mention or aggregate data from any other scans.
                6. INCLUDE EVERY FINDING: Do not summarize or omit findings. In Section 4, explain every single finding provided in the scan data.
                
                MANDATORY REPORT STRUCTURE (Follow these exact headers):
                
                # WebShield Security Assessment Report
                **Website Name:** {websiteName}
                **Website URL:** {websiteUrl}
                **Scan ID:** {scanId}
                **Scan Date:** {startedAt}
                **Report Generation Date:** [Current Date]
                **Assessment Type:** Automated Dynamic Application Security Testing (DAST)
                
                ---
                
                ## 1. Executive Summary
                - Purpose of the assessment
                - Website overview
                - Overall scan results summary
                - Total tests executed and total findings detected
                - Most important security concerns
                
                Include the Severity Summary Table:
                | Severity Level | Finding Count | Priority Level |
                |---|---|---|
                | CRITICAL | {count} | Immediate Remediation Required |
                | HIGH | {count} | High Priority Flaws |
                | MEDIUM | {count} | Moderate Risk Issues |
                | LOW | {count} | Best Practice / Hardening |
                | INFORMATIONAL | {count} | Security Observation Notes |
                | **TOTAL** | **{total}** | |
                
                ## 2. Overall Security Assessment
                Explain the website's security posture observed from this scan. Summarize key attack surface exposures and risks without inventing arbitrary numeric grades.
                
                ## 3. Critical Security Issues
                Detail all CRITICAL findings first. Include vulnerability name, affected URL, technical description, evidence, potential impact, and remediation steps.
                NOTE: If there are ZERO critical findings, explicitly state: "No Critical security vulnerabilities were identified during this assessment."
                
                ## 4. Detailed Security Findings
                Provide a structured, readable summary grouped by severity (High, Medium, Low, Informational) and vulnerability type.
                For each unique vulnerability type, provide concise sentences explaining the flaw, the potential impact, remediation guidance, and sample affected endpoints (mentioning total occurrences rather than repeating dozens of identical URLs). Keep it clear, professional, and well-organized in sentences.
                
                ## 5. Security Testing Methodology
                Explain WebShield's defensive assessment workflow: Breadth-First Search (BFS) crawler page discovery, form analysis, and non-destructive rule evaluation for security headers, cookie attributes, XSS probes, and SQL error signatures.
                
                ## 6. Tests Performed and Results
                Present a structured markdown table:
                | Test Category | Test Name | Execution Status | Result |
                List each test category and whether issues were found or no vulnerabilities observed. Distinguish executed vs inconclusive tests.
                
                ## 7. Technical Evidence
                Compile the technical evidence: affected URLs, HTTP methods, HTTP response headers, status codes, and excerpted detection responses.
                
                ## 8. Remediation Roadmap
                Provide a prioritized, practical roadmap for developers and system administrators:
                - Immediate (0-48 hours)
                - High Priority (1-2 weeks)
                - Medium Priority (30 days)
                - Low & Informational (Next release cycle)
                Include actionable code/header configuration directives.
                
                ## 9. Final Assessment
                Highlight urgent fixes, recommended next verification steps, and clear assessment limitations (e.g. testing was non-destructive and limited to the configured crawl scope).
                
                ## 10. Appendix
                - Scan configuration parameters (crawl depth, page limits, timeout)
                - Scan duration and page discovery metrics
                - Complete technical summary table
                """;
    }

    private String formatDuration(ScanRecord scan) {
        if (scan.getStartedAt() == null || scan.getCompletedAt() == null) {
            return "Not available in scan data.";
        }
        long seconds = Duration.between(scan.getStartedAt(), scan.getCompletedAt()).getSeconds();
        if (seconds < 60) {
            return seconds + " seconds";
        }
        return (seconds / 60) + " minutes " + (seconds % 60) + " seconds";
    }
}
