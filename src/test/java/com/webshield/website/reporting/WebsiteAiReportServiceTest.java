package com.webshield.website.reporting;

import com.webshield.api.llm.GeminiLlmProvider;
import com.webshield.api.llm.LlmConfiguration;
import com.webshield.api.llm.LlmService;
import com.webshield.assessment.models.ConfidenceLevel;
import com.webshield.assessment.models.Severity;
import com.webshield.database.repositories.FindingRepository;
import com.webshield.database.repositories.ScanRecord;
import com.webshield.database.repositories.ScanRepository;
import com.webshield.models.FindingEvidence;
import com.webshield.models.SecurityFinding;
import com.webshield.models.Website;
import com.webshield.website.WebsiteRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class WebsiteAiReportServiceTest {

    @Test
    @DisplayName("01: Gemini provider is registered and active in LlmConfiguration")
    void testGeminiProviderConfiguration() {
        LlmConfiguration config = LlmConfiguration.fromEnvironment();
        assertNotNull(config);
        assertEquals("gemini", config.providerName());
        assertTrue(config.enabled());
        assertNotNull(config.apiKey());
        assertFalse(config.apiKey().isBlank());
        assertEquals(LlmConfiguration.DEFAULT_MODEL, config.modelName());
    }

    @Test
    @DisplayName("02: WebsiteReportResult data model structure and PDF writer generation")
    void testWebsiteReportPdfWriterGeneration(@TempDir Path tempDir) throws Exception {
        Website website = new Website();
        website.setId(10L);
        website.setName("Blazedemo Airline Booking");
        website.setUrl("https://blazedemo.com");
        website.setDescription("Online flight reservation demonstration portal.");

        ScanRecord scan = new ScanRecord();
        scan.setId(17L);
        scan.setWebsiteId(10L);
        scan.setWebsiteName("Blazedemo Airline Booking");
        scan.setStatus("COMPLETED");
        scan.setCrawlDepth(2);
        scan.setMaxPages(25);
        scan.setTimeoutSeconds(30);
        scan.setPagesDiscovered(15);
        scan.setPagesTested(12);
        scan.setFindingsCount(4);
        scan.setStartedAt(LocalDateTime.now().minusMinutes(5));
        scan.setCompletedAt(LocalDateTime.now());

        SecurityFinding f1 = new SecurityFinding("Missing Strict-Transport-Security", "Security Headers", "https://blazedemo.com/vacation.html", Severity.HIGH);
        f1.setId(101L);
        f1.setVulnerabilityCode("WS-HDR-002");
        f1.setConfidenceLevel(ConfidenceLevel.CONFIRMED);
        f1.setDescription("The HTTP Strict-Transport-Security (HSTS) header is missing on an HTTPS endpoint.");
        f1.setRemediation("Add Strict-Transport-Security: max-age=31536000; includeSubDomains.");
        f1.setEvidence(new FindingEvidence("Header evaluation", "GET /vacation.html", "HTTP/1.1 200 OK\nServer: Apache", "Missing HSTS"));

        SecurityFinding f2 = new SecurityFinding("Missing Content-Security-Policy", "Security Headers", "https://blazedemo.com/index.php", Severity.HIGH);
        f2.setId(102L);
        f2.setVulnerabilityCode("WS-HDR-001");
        f2.setConfidenceLevel(ConfidenceLevel.CONFIRMED);
        f2.setDescription("No Content-Security-Policy header detected.");
        f2.setRemediation("Deploy a restrictive CSP directive policy.");

        List<SecurityFinding> findings = new ArrayList<>(List.of(f1, f2));
        for (int i = 0; i < 200; i++) {
            SecurityFinding extra = new SecurityFinding("Missing Content-Security-Policy", "Security Headers", "https://blazedemo.com/page" + i + ".html", Severity.HIGH);
            extra.setId((long) (200 + i));
            extra.setVulnerabilityCode("WS-HDR-001");
            extra.setDescription("The Content-Security-Policy (CSP) header is absent from HTTP responses.");
            extra.setRemediation("Define a strict Content-Security-Policy header.");
            findings.add(extra);
        }
        Map<String, Long> severityCounts = Map.of(
                "CRITICAL", 0L,
                "HIGH", 202L,
                "MEDIUM", 0L,
                "LOW", 0L,
                "INFORMATIONAL", 0L
        );

        String sampleReport = """
                # WebShield Security Assessment Report
                **Website Name:** Blazedemo Airline Booking
                **Website URL:** https://blazedemo.com
                **Scan ID:** 17
                
                ## 1. Executive Summary
                Purpose of assessment and findings breakdown.
                
                ## 2. Overall Security Assessment
                Observed risk posture.
                
                ## 3. Critical Security Issues
                No Critical security vulnerabilities were identified during this assessment.
                
                ## 4. Detailed Security Findings
                - [HIGH] Missing Strict-Transport-Security
                - [HIGH] Missing Content-Security-Policy
                
                ## 5. Security Testing Methodology
                Defensive crawling and rule execution.
                
                ## 6. Tests Performed and Results
                | Test Category | Test Name | Execution Status | Result |
                |---|---|---|---|
                | Security Headers | HSTS | EXECUTED | FINDINGS DETECTED |
                
                ## 7. Technical Evidence
                https://blazedemo.com/vacation.html
                
                ## 8. Remediation Roadmap
                Prioritized fixes.
                
                ## 9. Final Assessment
                Ongoing evaluation.
                
                ## 10. Appendix
                Scan ID #17 summary.
                """;

        WebsiteReportResult result = new WebsiteReportResult(
                17L, website, scan, findings, severityCounts, sampleReport, LocalDateTime.now(), "gemini-1.5-flash"
        );

        Path pdfFile = tempDir.resolve("Test_Report.pdf");
        File exported = WebsiteReportPdfWriter.writePdf(result, pdfFile);

        assertNotNull(exported);
        assertTrue(exported.exists());
        assertTrue(exported.length() > 500, "Exported PDF must have valid size");
    }

    @Test
    @DisplayName("03: Live Gemini report generation with active API key and model fallback")
    void testLiveGeminiReportGeneration() throws Exception {
        LlmConfiguration config = LlmConfiguration.fromEnvironment();
        GeminiLlmProvider provider = new GeminiLlmProvider();
        String report = provider.generateCompleteReport(
                "You are WebShield AI. Generate a 2-paragraph security overview.",
                "Target: https://blazedemo.com, Findings: 2 high severity header issues.",
                config
        );
        assertNotNull(report);
        assertFalse(report.isBlank());
        assertTrue(report.length() > 50);
    }
}
