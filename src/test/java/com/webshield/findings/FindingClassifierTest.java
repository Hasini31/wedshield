package com.webshield.findings;

import com.webshield.assessment.models.ConfidenceLevel;
import com.webshield.assessment.models.Severity;
import com.webshield.models.SecurityFinding;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("FindingClassifier Unit Tests")
class FindingClassifierTest {

    @Test
    @DisplayName("Severity weights match standard risk rankings")
    void testSeverityWeights() {
        assertEquals(10, FindingClassifier.getSeverityWeight(Severity.CRITICAL));
        assertEquals(7, FindingClassifier.getSeverityWeight(Severity.HIGH));
        assertEquals(4, FindingClassifier.getSeverityWeight(Severity.MEDIUM));
        assertEquals(2, FindingClassifier.getSeverityWeight(Severity.LOW));
        assertEquals(0, FindingClassifier.getSeverityWeight(Severity.INFORMATIONAL));
        assertEquals(0, FindingClassifier.getSeverityWeight(null));
    }

    @Test
    @DisplayName("isHigherSeverity evaluates hierarchical order correctly")
    void testIsHigherSeverity() {
        assertTrue(FindingClassifier.isHigherSeverity(Severity.CRITICAL, Severity.HIGH));
        assertTrue(FindingClassifier.isHigherSeverity(Severity.HIGH, Severity.MEDIUM));
        assertTrue(FindingClassifier.isHigherSeverity(Severity.MEDIUM, Severity.LOW));
        assertTrue(FindingClassifier.isHigherSeverity(Severity.LOW, Severity.INFORMATIONAL));
        assertFalse(FindingClassifier.isHigherSeverity(Severity.LOW, Severity.HIGH));
        assertFalse(FindingClassifier.isHigherSeverity(Severity.HIGH, Severity.HIGH));
    }

    @Test
    @DisplayName("calculateOverallRiskScore accumulates risk scores and caps at 100")
    void testCalculateOverallRiskScore() {
        SecurityFinding f1 = new SecurityFinding("Flaw 1", "Cat", "https://example.com", Severity.CRITICAL);
        SecurityFinding f2 = new SecurityFinding("Flaw 2", "Cat", "https://example.com", Severity.HIGH);
        SecurityFinding f3 = new SecurityFinding("Flaw 3", "Cat", "https://example.com", Severity.MEDIUM);

        int score = FindingClassifier.calculateOverallRiskScore(List.of(f1, f2, f3));
        assertEquals(21, score); // 10 + 7 + 4 = 21

        // Ignored statuses
        f1.setFindingStatus(FindingStatus.RESOLVED);
        f2.setFindingStatus(FindingStatus.FALSE_POSITIVE);
        assertEquals(4, FindingClassifier.calculateOverallRiskScore(List.of(f1, f2, f3)));
    }

    @Test
    @DisplayName("groupFindingsBySeverity aggregates finding counts")
    void testGroupFindingsBySeverity() {
        SecurityFinding f1 = new SecurityFinding("Crit", "Cat", "https://example.com", Severity.CRITICAL);
        SecurityFinding f2 = new SecurityFinding("Crit 2", "Cat", "https://example.com", Severity.CRITICAL);
        SecurityFinding f3 = new SecurityFinding("Low", "Cat", "https://example.com", Severity.LOW);

        Map<Severity, Long> counts = FindingClassifier.groupFindingsBySeverity(List.of(f1, f2, f3));
        assertEquals(2L, counts.get(Severity.CRITICAL));
        assertEquals(0L, counts.get(Severity.HIGH));
        assertEquals(0L, counts.get(Severity.MEDIUM));
        assertEquals(1L, counts.get(Severity.LOW));
        assertEquals(0L, counts.get(Severity.INFORMATIONAL));
    }

    @Test
    @DisplayName("inferConfidence accurately categorizes detection evidence")
    void testInferConfidence() {
        assertEquals(ConfidenceLevel.CONFIRMED,
                FindingClassifier.inferConfidence("Input reflection probe", "<script>alert(1)</script>"));
        assertEquals(ConfidenceLevel.CONFIRMED,
                FindingClassifier.inferConfidence("SQL error probe", "Syntax error in SQL statement"));
        assertEquals(ConfidenceLevel.POTENTIAL,
                FindingClassifier.inferConfidence("Generic check", "Missing header"));
        assertEquals(ConfidenceLevel.INFORMATIONAL,
                FindingClassifier.inferConfidence("Generic check", ""));
    }
}

