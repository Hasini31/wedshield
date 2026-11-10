package com.webshield.api.reporting;

/**
 * Custom runtime exception thrown when report generation, formatting, or file export fails.
 */
public class ApiReportException extends RuntimeException {

    private final String reportFormat;

    public ApiReportException(String message) {
        this(message, null, null);
    }

    public ApiReportException(String message, Throwable cause) {
        this(message, null, cause);
    }

    public ApiReportException(String message, String reportFormat, Throwable cause) {
        super(message, cause);
        this.reportFormat = reportFormat;
    }

    public String getReportFormat() {
        return reportFormat;
    }
}

