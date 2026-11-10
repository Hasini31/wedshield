package com.webshield.api.analysis;

import com.webshield.assessment.models.Severity;

/**
 * Standard severity rating for API security findings.
 */
public enum ApiFindingSeverity {
    CRITICAL(10),
    HIGH(7),
    MEDIUM(4),
    LOW(2),
    INFORMATIONAL(0);

    private final int weight;

    ApiFindingSeverity(int weight) {
        this.weight = weight;
    }

    public int getWeight() {
        return weight;
    }

    public Severity toModelSeverity() {
        return switch (this) {
            case CRITICAL -> Severity.CRITICAL;
            case HIGH -> Severity.HIGH;
            case MEDIUM -> Severity.MEDIUM;
            case LOW -> Severity.LOW;
            case INFORMATIONAL -> Severity.INFORMATIONAL;
        };
    }

    public static ApiFindingSeverity fromModelSeverity(Severity severity) {
        if (severity == null) {
            return INFORMATIONAL;
        }
        return switch (severity) {
            case CRITICAL -> CRITICAL;
            case HIGH -> HIGH;
            case MEDIUM -> MEDIUM;
            case LOW -> LOW;
            case INFORMATIONAL -> INFORMATIONAL;
        };
    }
}

