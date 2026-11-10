package com.webshield.findings;

import com.webshield.assessment.models.Severity;
import com.webshield.models.SecurityFinding;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("FindingService & History Unit Tests")
class FindingServiceTest {

    @Test
    @DisplayName("FindingStatus enum parses string representations safely")
    void testFindingStatusParsing() {
        assertEquals(FindingStatus.OPEN, FindingStatus.fromString("Open"));
        assertEquals(FindingStatus.UNDER_REVIEW, FindingStatus.fromString("Under Review"));
        assertEquals(FindingStatus.RESOLVED, FindingStatus.fromString("Resolved"));
        assertEquals(FindingStatus.FALSE_POSITIVE, FindingStatus.fromString("False Positive"));
        assertEquals(FindingStatus.OPEN, FindingStatus.fromString("Invalid"));
        assertEquals(FindingStatus.OPEN, FindingStatus.fromString(null));
    }

    @Test
    @DisplayName("FindingHistoryService logs and audits status transitions")
    void testHistoryAuditLogging() {
        FindingHistoryService history = new FindingHistoryService();
        history.recordStatusChange(101L, FindingStatus.OPEN, FindingStatus.UNDER_REVIEW, "Alice", "Investigating alert");
        history.recordStatusChange(101L, FindingStatus.UNDER_REVIEW, FindingStatus.FALSE_POSITIVE, "Bob", "Verified intentional behaviour");

        List<FindingHistoryService.FindingHistoryEntry> entries = history.getHistory(101L);
        assertEquals(2, entries.size());

        assertEquals(FindingStatus.OPEN, entries.get(0).previousStatus());
        assertEquals(FindingStatus.UNDER_REVIEW, entries.get(0).newStatus());
        assertEquals("Alice", entries.get(0).changedBy());

        assertEquals(FindingStatus.UNDER_REVIEW, entries.get(1).previousStatus());
        assertEquals(FindingStatus.FALSE_POSITIVE, entries.get(1).newStatus());
        assertEquals("Bob", entries.get(1).changedBy());
    }

    @Test
    @DisplayName("FindingService delegates deduplication correctly")
    void testServiceDeduplication() {
        FindingService service = new FindingService();
        SecurityFinding f1 = new SecurityFinding("Flaw", "Cat", "https://example.com", Severity.LOW);
        SecurityFinding f2 = new SecurityFinding("Flaw", "Cat", "https://example.com", Severity.LOW);

        List<SecurityFinding> dedup = service.deduplicateFindings(List.of(f1, f2));
        assertEquals(1, dedup.size());
    }
}

