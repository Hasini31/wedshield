package com.webshield.findings;

import com.webshield.assessment.models.AssessmentResult;
import com.webshield.assessment.models.ConfidenceLevel;
import com.webshield.assessment.models.Severity;
import com.webshield.models.SecurityFinding;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("FindingDeduplicator Unit Tests")
class FindingDeduplicatorTest {

    @Test
    @DisplayName("Empty or null input returns empty list")
    void testEmptyAndNull() {
        assertTrue(FindingDeduplicator.deduplicate(null).isEmpty());
        assertTrue(FindingDeduplicator.deduplicate(List.of()).isEmpty());
        assertTrue(FindingDeduplicator.deduplicateResults(1L, null).isEmpty());
    }

    @Test
    @DisplayName("Deduplicates identical findings and keeps higher severity")
    void testDeduplicateIdenticalKeepsHigherSeverity() {
        SecurityFinding f1 = new SecurityFinding("SQL Error", "SQL Injection", "https://example.com/search", Severity.MEDIUM);
        f1.setWebsiteId(1L);
        f1.setAffectedParam("q");

        SecurityFinding f2 = new SecurityFinding("SQL Error", "SQL Injection", "https://example.com/search", Severity.HIGH);
        f2.setWebsiteId(1L);
        f2.setAffectedParam("q");

        List<SecurityFinding> deduplicated = FindingDeduplicator.deduplicate(List.of(f1, f2));
        assertEquals(1, deduplicated.size());
        assertEquals(Severity.HIGH, deduplicated.get(0).getSeverity());
    }

    @Test
    @DisplayName("Keeps distinct findings when URLs or parameters differ")
    void testKeepsDistinctUrlsAndParams() {
        SecurityFinding f1 = new SecurityFinding("XSS", "Reflection", "https://example.com/page1", Severity.HIGH);
        f1.setWebsiteId(1L);
        f1.setAffectedParam("id");

        SecurityFinding f2 = new SecurityFinding("XSS", "Reflection", "https://example.com/page2", Severity.HIGH);
        f2.setWebsiteId(1L);
        f2.setAffectedParam("id");

        SecurityFinding f3 = new SecurityFinding("XSS", "Reflection", "https://example.com/page1", Severity.HIGH);
        f3.setWebsiteId(1L);
        f3.setAffectedParam("name");

        List<SecurityFinding> deduplicated = FindingDeduplicator.deduplicate(List.of(f1, f2, f3));
        assertEquals(3, deduplicated.size());
    }

    @Test
    @DisplayName("Case-insensitively deduplicates URLs and categories")
    void testCaseInsensitiveNormalization() {
        SecurityFinding f1 = new SecurityFinding("Missing CSP", "Security Headers", "HTTPS://EXAMPLE.COM/ABOUT", Severity.LOW);
        f1.setWebsiteId(1L);
        f1.setAffectedParam("");

        SecurityFinding f2 = new SecurityFinding("Missing CSP", "SECURITY HEADERS", "https://example.com/about", Severity.LOW);
        f2.setWebsiteId(1L);
        f2.setAffectedParam(null);

        List<SecurityFinding> deduplicated = FindingDeduplicator.deduplicate(List.of(f1, f2));
        assertEquals(1, deduplicated.size());
    }

    @Test
    @DisplayName("Deduplicates AssessmentResult pipeline entities correctly")
    void testDeduplicateResults() {
        AssessmentResult ar1 = new AssessmentResult("Header check", "Headers", "WS-HDR-001",
                "https://example.com", null, "GET", Severity.LOW, ConfidenceLevel.POTENTIAL,
                "Desc", "Ev", "Method", "Rem");
        AssessmentResult ar2 = new AssessmentResult("Header check", "Headers", "WS-HDR-001",
                "https://example.com", null, "GET", Severity.LOW, ConfidenceLevel.POTENTIAL,
                "Desc", "Ev", "Method", "Rem");

        List<AssessmentResult> results = FindingDeduplicator.deduplicateResults(1L, List.of(ar1, ar2));
        assertEquals(1, results.size());
    }
}

