package com.webshield.api.reporting;

import java.nio.file.Path;

/**
 * Strategy interface for generating API security assessment reports in different formats.
 */
public interface ApiReportGenerator {

    /**
     * Generates a security assessment report file in the designated output directory.
     *
     * @param data            aggregated scan, finding, and project information
     * @param configuration   report section toggles and format settings
     * @param outputDirectory target directory where the generated file must be stored
     * @return export result containing file path and size
     * @throws ApiReportException if formatting, path traversal, or I/O fails
     */
    ApiReportExportResult generate(ApiReportData data, ApiReportConfiguration configuration, Path outputDirectory) throws ApiReportException;

    /**
     * Supported format name (e.g. "PDF", "HTML").
     */
    String getSupportedFormat();
}

