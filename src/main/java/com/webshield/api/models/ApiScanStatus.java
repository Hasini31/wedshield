package com.webshield.api.models;

/**
 * Enumeration representing the complete lifecycle states of an API security test scan.
 */
public enum ApiScanStatus {
    PENDING("Pending", false),
    INITIALIZING("Initializing", false),
    GENERATING("Generating Tests", false),
    EXECUTING("Executing Dispatches", false),
    ANALYZING("Analyzing Responses", false),
    SAVING_RESULTS("Saving Results", false),
    COMPLETED("Completed", true),
    FAILED("Failed", true),
    CANCELLED("Cancelled", true);

    private final String displayName;
    private final boolean terminal;

    ApiScanStatus(String displayName, boolean terminal) {
        this.displayName = displayName;
        this.terminal = terminal;
    }

    public String getDisplayName() {
        return displayName;
    }

    public boolean isTerminal() {
        return terminal;
    }

    public boolean isActive() {
        return !terminal && this != PENDING;
    }

    public static ApiScanStatus fromString(String val) {
        if (val == null || val.isBlank()) return PENDING;
        try {
            return ApiScanStatus.valueOf(val.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return PENDING;
        }
    }
}

