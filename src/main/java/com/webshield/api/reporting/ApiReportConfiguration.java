package com.webshield.api.reporting;

import java.io.Serializable;

/**
 * Immutable configuration controlling report generation sections, formatting, and AI assistance.
 */
public record ApiReportConfiguration(
        String reportTitle,
        String reportFormat,
        boolean includeExecutiveSummary,
        boolean includeScope,
        boolean includeMethodology,
        boolean includeVulnerabilityOverview,
        boolean includeDetailedFindings,
        boolean includeStatistics,
        boolean includeRemediation,
        boolean includeLimitations,
        boolean includeAiExplanations,
        boolean externalSharingConsent,
        String outputDirectory
) implements Serializable {

    public static final String FORMAT_PDF = "PDF";
    public static final String FORMAT_HTML = "HTML";
    public static final String DEFAULT_OUTPUT_DIR = "reports/api";

    public ApiReportConfiguration {
        reportTitle = (reportTitle != null && !reportTitle.isBlank()) ? reportTitle : "WebShield API Security Assessment Report";
        reportFormat = (reportFormat != null && reportFormat.equalsIgnoreCase(FORMAT_HTML)) ? FORMAT_HTML : FORMAT_PDF;
        outputDirectory = (outputDirectory != null && !outputDirectory.isBlank()) ? outputDirectory : DEFAULT_OUTPUT_DIR;
    }

    public static ApiReportConfiguration defaultPdf() {
        return new ApiReportConfiguration(
                "WebShield API Security Assessment Report",
                FORMAT_PDF,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
                DEFAULT_OUTPUT_DIR
        );
    }

    public static ApiReportConfiguration defaultHtml() {
        return new ApiReportConfiguration(
                "WebShield API Security Assessment Report",
                FORMAT_HTML,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                false,
                false,
                DEFAULT_OUTPUT_DIR
        );
    }
}

