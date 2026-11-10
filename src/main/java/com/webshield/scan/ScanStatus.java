package com.webshield.scan;

/**
 * Enumeration representing the complete lifecycle states of a security scan.
 */
public enum ScanStatus {

    /**
     * Scan has been configured and queued for execution.
     */
    PENDING("Pending", false),

    /**
     * Scan parameters are being validated and scan record initialized.
     */
    INITIALIZING("Initializing", false),

    /**
     * Crawler is actively traversing and mapping target website structure.
     */
    CRAWLING("Crawling", false),

    /**
     * Security assessment rules are actively inspecting discovered endpoints.
     */
    ASSESSING("Assessing", false),

    /**
     * Findings are being deduplicated, classified, and persisted to the database.
     */
    SAVING_RESULTS("Saving Results", false),

    /**
     * Scan completed successfully and all findings have been saved.
     */
    COMPLETED("Completed", true),

    /**
     * Scan failed due to an unrecoverable network, engine, or database error.
     */
    FAILED("Failed", true),

    /**
     * Scan was cooperatively cancelled by user request.
     */
    CANCELLED("Cancelled", true);

    private final String displayName;
    private final boolean terminal;

    ScanStatus(String displayName, boolean terminal) {
        this.displayName = displayName;
        this.terminal = terminal;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * Returns true if this is a final terminal state (COMPLETED, FAILED, CANCELLED).
     */
    public boolean isTerminal() {
        return terminal;
    }

    /**
     * Returns true if this is an active in-progress state.
     */
    public boolean isActive() {
        return !terminal && this != PENDING;
    }

    public static ScanStatus fromString(String val) {
        if (val == null || val.isBlank()) return PENDING;
        try {
            return ScanStatus.valueOf(val.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return PENDING;
        }
    }
}

