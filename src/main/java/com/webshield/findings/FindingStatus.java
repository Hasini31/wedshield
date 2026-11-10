package com.webshield.findings;

/**
 * Lifecycle review status for a vulnerability finding.
 * Allows analysts to triage, confirm, resolve, or mark findings as false positives.
 */
public enum FindingStatus {

    /**
     * Active finding awaiting triage and review.
     */
    OPEN("Open"),

    /**
     * Finding is actively being investigated by the security team.
     */
    UNDER_REVIEW("Under Review"),

    /**
     * Vulnerability remediation verified and closed.
     */
    RESOLVED("Resolved"),

    /**
     * Verified by analyst as an intentional design or false positive.
     */
    FALSE_POSITIVE("False Positive");

    private final String displayName;

    FindingStatus(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static FindingStatus fromString(String val) {
        if (val == null || val.isBlank()) return OPEN;
        String clean = val.trim().toUpperCase().replace(" ", "_");
        try {
            return FindingStatus.valueOf(clean);
        } catch (IllegalArgumentException e) {
            return OPEN;
        }
    }
}

