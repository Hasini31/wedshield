package com.webshield.api.reporting;

import com.webshield.api.dto.ApiFindingDto;
import com.webshield.api.dto.ApiScanDto;
import com.webshield.api.llm.LlmFindingExplanation;
import com.webshield.api.reporting.pdf.SimplePdfWriter;
import com.webshield.api.analysis.RedactionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Generates executive-ready, professional PDF security assessment reports
 * using pure Java 21 and the internal {@link SimplePdfWriter} engine.
 */
public class PdfReportGenerator implements ApiReportGenerator {

    private static final Logger log = LoggerFactory.getLogger(PdfReportGenerator.class);
    private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm:ss");

    @Override
    public ApiReportExportResult generate(ApiReportData data, ApiReportConfiguration config, Path outputDirectory) throws ApiReportException {
        if (data == null || config == null || outputDirectory == null) {
            throw new ApiReportException("Report data, configuration, and output directory must not be null");
        }

        try {
            Files.createDirectories(outputDirectory);
            String safeBaseName = sanitizeFileName("WebShield_API_Report_" + data.reportIdentifier() + "_" + data.scanName());
            Path targetFile = outputDirectory.resolve(safeBaseName + ".pdf").normalize().toAbsolutePath();

            if (!targetFile.startsWith(outputDirectory.toAbsolutePath())) {
                throw new SecurityException("Potential path traversal attempt detected in PDF report target path: " + targetFile);
            }

            SimplePdfWriter writer = new SimplePdfWriter();
            buildPdfContent(writer, data, config);

            try (OutputStream out = new BufferedOutputStream(new FileOutputStream(targetFile.toFile()))) {
                writer.writeTo(out);
            }

            long fileSizeBytes = Files.size(targetFile);
            log.info("Successfully generated PDF report at: {} ({} bytes, {} pages)", targetFile, fileSizeBytes, writer.getPageCount());
            return ApiReportExportResult.successful(data.reportIdentifier(), targetFile, getSupportedFormat(), fileSizeBytes);
        } catch (IOException e) {
            log.error("Failed to write PDF report file: {}", e.getMessage(), e);
            throw new ApiReportException("Failed to generate PDF report: " + e.getMessage(), getSupportedFormat(), e);
        }
    }

    @Override
    public String getSupportedFormat() {
        return ApiReportConfiguration.FORMAT_PDF;
    }

    private void buildPdfContent(SimplePdfWriter writer, ApiReportData data, ApiReportConfiguration config) {
        // 1. Cover Page
        buildCoverPage(writer, data, config);

        // 2. Executive Summary
        if (config.includeExecutiveSummary()) {
            writer.newPage();
            writer.addSectionTitle("1. Executive Summary");
            writer.addParagraph("An automated dynamic API security assessment was performed to discover schema violations, authentication vulnerabilities, injection vectors, and sensitive data leakage.",
                    SimplePdfWriter.MARGIN, "F1", 9.5f, 0.35f, 0.40f, 0.50f, SimplePdfWriter.CONTENT_WIDTH);

            // Summary Metrics Grid (drawn as boxes)
            float startY = writer.getCurrentY() - 10.0f;
            float boxWidth = (SimplePdfWriter.CONTENT_WIDTH - 25.0f) / 6.0f;
            float boxHeight = 44.0f;

            drawMetricBox(writer, SimplePdfWriter.MARGIN + (0 * (boxWidth + 5.0f)), startY, boxWidth, boxHeight, "Critical", String.valueOf(data.getCriticalCount()), 0.86f, 0.15f, 0.15f);
            drawMetricBox(writer, SimplePdfWriter.MARGIN + (1 * (boxWidth + 5.0f)), startY, boxWidth, boxHeight, "High", String.valueOf(data.getHighCount()), 0.92f, 0.35f, 0.05f);
            drawMetricBox(writer, SimplePdfWriter.MARGIN + (2 * (boxWidth + 5.0f)), startY, boxWidth, boxHeight, "Medium", String.valueOf(data.getMediumCount()), 0.85f, 0.47f, 0.02f);
            drawMetricBox(writer, SimplePdfWriter.MARGIN + (3 * (boxWidth + 5.0f)), startY, boxWidth, boxHeight, "Low", String.valueOf(data.getLowCount()), 0.15f, 0.39f, 0.92f);
            drawMetricBox(writer, SimplePdfWriter.MARGIN + (4 * (boxWidth + 5.0f)), startY, boxWidth, boxHeight, "Info", String.valueOf(data.getInfoCount()), 0.39f, 0.45f, 0.55f);
            drawMetricBox(writer, SimplePdfWriter.MARGIN + (5 * (boxWidth + 5.0f)), startY, boxWidth, boxHeight, "Total", String.valueOf(data.findings().size()), 0.21f, 0.42f, 0.90f);

            // Advance current Y
            writer.checkPageSpace(boxHeight + 15.0f);

            ApiScanDto scan = data.scan();
            String obs = String.format("During this scan, %d HTTP requests were executed against %d API endpoints over %s. ",
                    scan != null ? scan.totalExecutedRequests() : 0,
                    scan != null ? scan.totalEndpoints() : 0,
                    scan != null && scan.durationMs() > 0 ? (scan.durationMs() / 1000.0) + "s" : "N/A");

            if (data.getCriticalCount() > 0 || data.getHighCount() > 0) {
                obs += "CRITICAL and HIGH severity vulnerabilities were discovered that warrant immediate remediation before deployment.";
            } else if (data.findings().isEmpty()) {
                obs += "No active vulnerabilities were identified under the configured objectives.";
            } else {
                obs += "Identified observations primarily relate to defense-in-depth header controls and error handling.";
            }
            writer.addCalloutBox("Assessment Verdict & Observations", obs, 0.21f, 0.42f, 0.90f);
        }

        // 3. Assessment Scope
        if (config.includeScope()) {
            writer.addSectionTitle("2. Assessment Scope");
            String[] headers = {"Parameter", "Specification Detail"};
            float[] colWidths = {160.0f, 355.0f};
            List<String[]> rows = new ArrayList<>();
            rows.add(new String[]{"API Project", data.project() != null ? data.project().getName() : "API Project"});
            rows.add(new String[]{"Target Base URL", data.project() != null && data.project().getSourceUrl() != null ? data.project().getSourceUrl() : "Derived from OpenAPI"});
            rows.add(new String[]{"Specification Format", data.project() != null ? data.project().getSpecFormat() + " (" + data.project().getSpecType() + ")" : "OpenAPI 3.0"});
            rows.add(new String[]{"Tested HTTP Methods", "GET, POST, PUT, DELETE, PATCH"});
            rows.add(new String[]{"Endpoint Coverage", data.statistics().map(s -> String.format("%.1f%%", s.coveragePercentage())).orElse("N/A")});
            rows.add(new String[]{"Test Categories", "Schema-Aware Valid, Boundary Values, Invalid Payloads, Mutation, MIO"});
            writer.addTable(headers, colWidths, rows);
        }

        // 4. Testing Methodology
        if (config.includeMethodology()) {
            writer.addSectionTitle("3. Testing Methodology");
            writer.addParagraph("WebShield combines schema-driven baseline synthesis, boundary value exploration, input mutation, evolutionary search (MIO), and passive response analysis (OWASP ZAP inspired).",
                    SimplePdfWriter.MARGIN, "F1", 9.0f, 0.25f, 0.30f, 0.40f, SimplePdfWriter.CONTENT_WIDTH);

            String[] mHeaders = {"Stage", "Objective Description"};
            float[] mColWidths = {140.0f, 375.0f};
            List<String[]> mRows = List.of(
                    new String[]{"1. Spec Parsing", "Extracts schemas, parameters, constraints, and HTTP endpoints."},
                    new String[]{"2. Test Generation", "Produces schema-aware valid, boundary, and negative payloads."},
                    new String[]{"3. Mutation Engine", "Applies type mutations, SQLi/XSS fuzzing, and structural shifts."},
                    new String[]{"4. Evolutionary Search", "Optimizes test suites using Many Independent Objective (MIO)."},
                    new String[]{"5. HTTP Execution", "Safely executes HTTP requests with timeout and safety controls."},
                    new String[]{"6. Security Analysis", "Evaluates responses against OWASP API Security rules."}
            );
            writer.addTable(mHeaders, mColWidths, mRows);
        }

        // 5. Vulnerability Overview
        if (config.includeVulnerabilityOverview()) {
            writer.addSectionTitle("4. Vulnerability Overview");

            writer.addSubSectionTitle("OWASP API Security Top 10 Distribution");
            String[] oHeaders = {"OWASP Category", "Findings Count"};
            float[] oWidths = {365.0f, 150.0f};
            List<String[]> oRows = new ArrayList<>();
            Map<String, Integer> owaspMap = data.getOwaspCategoryCounts();
            if (owaspMap.isEmpty()) {
                oRows.add(new String[]{"No OWASP categorized vulnerabilities detected.", "0"});
            } else {
                for (Map.Entry<String, Integer> e : owaspMap.entrySet()) {
                    oRows.add(new String[]{e.getKey(), String.valueOf(e.getValue())});
                }
            }
            writer.addTable(oHeaders, oWidths, oRows);

            writer.addSubSectionTitle("Common Weakness Enumeration (CWE) Mapping");
            String[] cHeaders = {"CWE Identifier", "Instances"};
            float[] cWidths = {365.0f, 150.0f};
            List<String[]> cRows = new ArrayList<>();
            Map<String, Integer> cweMap = data.getCweCounts();
            if (cweMap.isEmpty()) {
                cRows.add(new String[]{"No CWE mapped weaknesses detected.", "0"});
            } else {
                for (Map.Entry<String, Integer> e : cweMap.entrySet()) {
                    cRows.add(new String[]{e.getKey(), String.valueOf(e.getValue())});
                }
            }
            writer.addTable(cHeaders, cWidths, cRows);
        }

        // 6. Detailed Findings
        if (config.includeDetailedFindings()) {
            writer.newPage();
            writer.addSectionTitle("5. Detailed Security Findings");

            List<ApiFindingDto> findings = data.findings();
            if (findings.isEmpty()) {
                writer.addParagraph("No security findings were identified during this assessment.",
                        SimplePdfWriter.MARGIN, "F1", 10.0f, 0.40f, 0.45f, 0.55f, SimplePdfWriter.CONTENT_WIDTH);
            } else {
                int index = 1;
                for (ApiFindingDto f : findings) {
                    writer.checkPageSpace(140.0f);

                    float r = 0.39f, g = 0.45f, b = 0.55f;
                    if ("CRITICAL".equalsIgnoreCase(f.severity())) { r = 0.86f; g = 0.15f; b = 0.15f; }
                    else if ("HIGH".equalsIgnoreCase(f.severity())) { r = 0.92f; g = 0.35f; b = 0.05f; }
                    else if ("MEDIUM".equalsIgnoreCase(f.severity())) { r = 0.85f; g = 0.47f; b = 0.02f; }
                    else if ("LOW".equalsIgnoreCase(f.severity())) { r = 0.15f; g = 0.39f; b = 0.92f; }

                    // Finding Header Banner
                    String fTitle = "#" + (index++) + " " + f.title() + " [" + f.severity() + "]";
                    writer.addText(fTitle, SimplePdfWriter.MARGIN, writer.getCurrentY(), "F2", 11.0f, r, g, b);
                    writer.drawLine(SimplePdfWriter.MARGIN, writer.getCurrentY() - 2.0f, SimplePdfWriter.MARGIN + SimplePdfWriter.CONTENT_WIDTH, writer.getCurrentY() - 2.0f, 0.85f, 0.88f, 0.92f, 1.0f);

                    // Finding Meta
                    String meta = String.format("Endpoint: %s %s  |  Confidence: %s  |  OWASP: %s  |  CWE: %s",
                            f.httpMethod() != null ? f.httpMethod() : "",
                            f.endpointPath() != null ? f.endpointPath() : "/",
                            f.confidence(),
                            f.owaspCategory() != null ? f.owaspCategory() : "—",
                            f.cweId() != null ? f.cweId() : "—");
                    writer.addParagraph(meta, SimplePdfWriter.MARGIN, "F2", 8.0f, 0.35f, 0.40f, 0.50f, SimplePdfWriter.CONTENT_WIDTH);

                    // Description
                    if (f.description() != null && !f.description().isBlank()) {
                        writer.addParagraph("Description: " + f.description(), SimplePdfWriter.MARGIN, "F1", 8.5f, 0.20f, 0.25f, 0.35f, SimplePdfWriter.CONTENT_WIDTH);
                    }

                    // Observed Evidence
                    if (f.evidence() != null && !f.evidence().isBlank()) {
                        writer.addText("Observed Evidence:", SimplePdfWriter.MARGIN, writer.getCurrentY(), "F2", 8.0f, 0.35f, 0.40f, 0.50f);
                        writer.addCodeBlock(RedactionUtils.redactSensitiveData(f.evidence()), SimplePdfWriter.MARGIN, SimplePdfWriter.CONTENT_WIDTH);
                    }

                    // Remediation
                    String rem = f.remediation() != null && !f.remediation().isBlank()
                            ? f.remediation() : "Enforce strict input validation, rate limiting, and standard authorization controls.";
                    writer.addParagraph("Remediation: " + rem, SimplePdfWriter.MARGIN, "F1", 8.5f, 0.10f, 0.50f, 0.25f, SimplePdfWriter.CONTENT_WIDTH);

                    // Optional AI Explanation Callout
                    if (config.includeAiExplanations() && data.aiExplanations().containsKey(f.id())) {
                        LlmFindingExplanation ai = data.aiExplanations().get(f.id());
                        if (ai != null) {
                            String aiBody = "Summary: " + ai.summary() + "\n" +
                                            "Impact: " + ai.potentialImpact() + "\n" +
                                            "Remediation: " + ai.remediationGuide() + "\n" +
                                            "[" + ai.disclaimer() + "]";
                            writer.addCalloutBox("AI-Assisted Advisory (" + ai.providerName() + ")", aiBody, 0.49f, 0.23f, 0.93f); // Purple
                        }
                    }

                    writer.checkPageSpace(15.0f);
                }
            }
        }

        // 7. Scan Statistics
        if (config.includeStatistics()) {
            writer.addSectionTitle("6. Scan Execution Statistics");
            String[] sHeaders = {"Metric Description", "Measured Value"};
            float[] sColWidths = {280.0f, 235.0f};
            List<String[]> sRows = new ArrayList<>();
            ApiScanDto scan = data.scan();
            if (scan != null) {
                sRows.add(new String[]{"Total Generated Test Cases", String.valueOf(scan.totalGeneratedTestCases())});
                sRows.add(new String[]{"Total Executed Requests", String.valueOf(scan.totalExecutedRequests())});
                sRows.add(new String[]{"Total Target Endpoints", String.valueOf(scan.totalEndpoints())});
                sRows.add(new String[]{"Scan Execution Duration", scan.durationMs() > 0 ? (scan.durationMs() / 1000.0) + "s" : "—"});
            }
            data.statistics().ifPresent(stats -> {
                sRows.add(new String[]{"Successful Responses (2xx)", String.valueOf(stats.status2xxCount())});
                sRows.add(new String[]{"Client Error Responses (4xx)", String.valueOf(stats.status4xxCount())});
                sRows.add(new String[]{"Server Error Responses (5xx)", String.valueOf(stats.status5xxCount())});
                sRows.add(new String[]{"Connection Failures / Errors", String.valueOf(stats.errorOutcomesCount())});
                sRows.add(new String[]{"Average Response Latency", String.format("%.1f ms", stats.avgResponseTimeMs())});
                sRows.add(new String[]{"Endpoint Coverage Percentage", String.format("%.1f%%", stats.coveragePercentage())});
            });
            writer.addTable(sHeaders, sColWidths, sRows);
        }

        // 8. Remediation Roadmap
        if (config.includeRemediation()) {
            writer.addSectionTitle("7. Prioritized Remediation Roadmap");
            writer.addCalloutBox("Priority 0: Immediate Action (Critical & High)",
                    "Remediate authentication bypass, injection weaknesses, and sensitive data leakage before production release. Revoke any leaked credentials.",
                    0.86f, 0.15f, 0.15f);

            writer.addCalloutBox("Priority 1: Near-Term Hardening (Medium)",
                    "Enforce strict schema validation on all incoming query/body inputs, suppress stack traces, and enforce timeout thresholds.",
                    0.85f, 0.47f, 0.02f);

            writer.addCalloutBox("Priority 2: Defense-in-Depth (Low & Informational)",
                    "Deploy standard security headers (Content-Security-Policy, X-Content-Type-Options) and align OpenAPI contracts with live behavior.",
                    0.15f, 0.39f, 0.92f);
        }

        // 9. Limitations & Disclaimer
        if (config.includeLimitations()) {
            writer.addSectionTitle("8. Limitations & Legal Disclaimer");
            String disclaimerText =
                    "This security report was compiled using automated dynamic testing techniques. Automated testing provides broad " +
                    "coverage against standard vulnerability patterns, but cannot guarantee the absence of all vulnerabilities (e.g. complex " +
                    "multi-user business logic bypasses). All reported findings represent indicators requiring human security validation. " +
                    "This report does NOT constitute formal regulatory compliance certification (such as PCI-DSS, SOC 2, or ISO 27001).";
            writer.addCalloutBox("Testing Scope & Disclaimer", disclaimerText, 0.35f, 0.40f, 0.50f);
        }
    }

    private void buildCoverPage(SimplePdfWriter writer, ApiReportData data, ApiReportConfiguration config) {
        // Dark Navy Banner Box
        writer.drawRect(0, SimplePdfWriter.PAGE_HEIGHT - 220.0f, SimplePdfWriter.PAGE_WIDTH, 220.0f, 0.09f, 0.14f, 0.22f, true); // #172338
        // Royal Blue Accent Stripe
        writer.drawRect(0, SimplePdfWriter.PAGE_HEIGHT - 226.0f, SimplePdfWriter.PAGE_WIDTH, 6.0f, 0.21f, 0.42f, 0.90f, true); // #356AE6

        // WebShield Brand
        writer.addText("WebShield Security Platform", SimplePdfWriter.MARGIN, SimplePdfWriter.PAGE_HEIGHT - 75.0f, "F2", 22.0f, 1.0f, 1.0f, 1.0f);
        writer.addText("AUTOMATED API SECURITY TESTING ENGINE", SimplePdfWriter.MARGIN, SimplePdfWriter.PAGE_HEIGHT - 95.0f, "F2", 9.0f, 0.58f, 0.64f, 0.72f);

        // Report Title
        writer.addText(config.reportTitle(), SimplePdfWriter.MARGIN, SimplePdfWriter.PAGE_HEIGHT - 145.0f, "F2", 16.0f, 1.0f, 1.0f, 1.0f);
        writer.addText("Comprehensive Dynamic Vulnerability Assessment", SimplePdfWriter.MARGIN, SimplePdfWriter.PAGE_HEIGHT - 165.0f, "F1", 11.0f, 0.85f, 0.88f, 0.92f);

        // Cover Page Meta Table
        float metaY = SimplePdfWriter.PAGE_HEIGHT - 280.0f;
        writer.addText("Assessment Report Details", SimplePdfWriter.MARGIN, metaY, "F2", 13.0f, 0.09f, 0.14f, 0.22f);
        writer.drawLine(SimplePdfWriter.MARGIN, metaY - 4.0f, SimplePdfWriter.MARGIN + SimplePdfWriter.CONTENT_WIDTH, metaY - 4.0f, 0.85f, 0.88f, 0.92f, 1.0f);

        String[] cHeaders = {"Attribute", "Assessment Value"};
        float[] cWidths = {160.0f, 355.0f};
        List<String[]> cRows = List.of(
                new String[]{"Target Application", data.targetApplication()},
                new String[]{"Scan Execution Name", data.scanName()},
                new String[]{"Report Identifier", data.reportIdentifier()},
                new String[]{"Assessment Date", data.generatedAt().format(DATE_FMT)},
                new String[]{"Total Identified Findings", String.valueOf(data.findings().size())},
                new String[]{"Critical / High Vulnerabilities", data.getCriticalCount() + " Critical, " + data.getHighCount() + " High"},
                new String[]{"Classification", "CONFIDENTIAL - AUTHORIZED SECURITY PERSONNEL ONLY"}
        );
        writer.addTable(cHeaders, cWidths, cRows);

        // Confidentiality Box at bottom of cover
        String notice = "CONFIDENTIALITY NOTICE: This document contains proprietary security analysis and vulnerability details " +
                "for authorized internal personnel only. Unauthorized distribution, copying, or dissemination is strictly prohibited.";
        writer.addCalloutBox("Confidential Document", notice, 0.86f, 0.15f, 0.15f);
    }

    private void drawMetricBox(SimplePdfWriter writer, float x, float y, float w, float h, String label, String val, float r, float g, float b) {
        // Outline box and light background
        writer.drawRect(x, y - h, w, h, 0.98f, 0.99f, 1.0f, true);
        writer.drawRect(x, y - h, w, h, 0.85f, 0.88f, 0.92f, false);
        // Color top bar
        writer.drawRect(x, y - 3.0f, w, 3.0f, r, g, b, true);

        // Value
        writer.addText(val, x + 10.0f, y - 22.0f, "F2", 15.0f, r, g, b);
        // Label
        writer.addText(label.toUpperCase(), x + 10.0f, y - 35.0f, "F2", 7.5f, 0.45f, 0.50f, 0.60f);
    }

    private String sanitizeFileName(String name) {
        return name.replace("..", "_").replaceAll("[^a-zA-Z0-9_-]", "_");
    }
}
