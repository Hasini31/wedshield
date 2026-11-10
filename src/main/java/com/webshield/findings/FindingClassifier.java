package com.webshield.findings;

import com.webshield.assessment.models.ConfidenceLevel;
import com.webshield.assessment.models.Severity;
import com.webshield.models.SecurityFinding;

import java.util.Collection;
import java.util.EnumMap;
import java.util.Map;

/**
 * Standardizes vulnerability severity classification, risk weighting, and confidence determination.
 */
public class FindingClassifier {

    /**
     * Numerical weight assigned to each severity level for aggregate risk calculation.
     */
    public static int getSeverityWeight(Severity severity) {
        if (severity == null) return 0;
        return switch (severity) {
            case CRITICAL -> 10;
            case HIGH -> 7;
            case MEDIUM -> 4;
            case LOW -> 2;
            case INFORMATIONAL -> 0;
        };
    }

    /**
     * Calculates an aggregate 0-100 risk score based on active findings and their severities.
     */
    public static int calculateOverallRiskScore(Collection<SecurityFinding> findings) {
        if (findings == null || findings.isEmpty()) return 0;

        int rawScore = 0;
        for (SecurityFinding f : findings) {
            // Ignore resolved or false positive findings in risk calculation
            if (f.getFindingStatus() == FindingStatus.RESOLVED || f.getFindingStatus() == FindingStatus.FALSE_POSITIVE) {
                continue;
            }
            rawScore += getSeverityWeight(f.getSeverity());
        }

        // Cap at 100
        return Math.min(100, rawScore);
    }

    /**
     * Returns true if severity A is strictly greater than severity B.
     */
    public static boolean isHigherSeverity(Severity a, Severity b) {
        if (a == null) return false;
        if (b == null) return true;
        return getSeverityWeight(a) > getSeverityWeight(b);
    }

    /**
     * Counts findings grouped by severity.
     */
    public static Map<Severity, Long> groupFindingsBySeverity(Collection<SecurityFinding> findings) {
        Map<Severity, Long> counts = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            counts.put(s, 0L);
        }
        if (findings != null) {
            for (SecurityFinding f : findings) {
                Severity s = f.getSeverity() != null ? f.getSeverity() : Severity.INFORMATIONAL;
                counts.put(s, counts.get(s) + 1);
            }
        }
        return counts;
    }

    /**
     * Classifies confidence level based on detection heuristic and evidence presence.
     */
    public static ConfidenceLevel inferConfidence(String detectionMethod, String evidence) {
        if (evidence == null || evidence.isBlank()) {
            return ConfidenceLevel.INFORMATIONAL;
        }
        if (detectionMethod != null && detectionMethod.toLowerCase().contains("reflection")) {
            return ConfidenceLevel.CONFIRMED;
        }
        if (detectionMethod != null && detectionMethod.toLowerCase().contains("sql")) {
            return ConfidenceLevel.CONFIRMED;
        }
        return ConfidenceLevel.POTENTIAL;
    }
}

