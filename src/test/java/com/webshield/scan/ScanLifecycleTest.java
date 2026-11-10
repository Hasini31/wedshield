package com.webshield.scan;

import com.webshield.assessment.models.Severity;
import com.webshield.models.SecurityFinding;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Scan Lifecycle & Result Unit Tests")
class ScanLifecycleTest {

    @Test
    @DisplayName("ScanStatus states categorize active and terminal phases accurately")
    void testScanStatusClassification() {
        assertTrue(ScanStatus.COMPLETED.isTerminal());
        assertTrue(ScanStatus.FAILED.isTerminal());
        assertTrue(ScanStatus.CANCELLED.isTerminal());

        assertFalse(ScanStatus.INITIALIZING.isTerminal());
        assertFalse(ScanStatus.CRAWLING.isTerminal());
        assertFalse(ScanStatus.ASSESSING.isTerminal());
        assertFalse(ScanStatus.SAVING_RESULTS.isTerminal());
        assertFalse(ScanStatus.PENDING.isTerminal());

        assertTrue(ScanStatus.CRAWLING.isActive());
        assertTrue(ScanStatus.ASSESSING.isActive());
        assertFalse(ScanStatus.PENDING.isActive());
        assertFalse(ScanStatus.COMPLETED.isActive());

        assertEquals(ScanStatus.CRAWLING, ScanStatus.fromString("CRAWLING"));
        assertEquals(ScanStatus.PENDING, ScanStatus.fromString("UNKNOWN"));
        assertEquals(ScanStatus.PENDING, ScanStatus.fromString(null));
    }

    @Test
    @DisplayName("ScanExecutionResult factory calculates duration and severity breakdowns")
    void testScanExecutionResultCompleted() {
        LocalDateTime start = LocalDateTime.now().minusSeconds(15);
        LocalDateTime end = LocalDateTime.now();

        SecurityFinding f1 = new SecurityFinding("Critical Vuln", "Cat", "https://example.com", Severity.CRITICAL);
        SecurityFinding f2 = new SecurityFinding("High Vuln", "Cat", "https://example.com", Severity.HIGH);
        SecurityFinding f3 = new SecurityFinding("Info Note", "Cat", "https://example.com", Severity.INFORMATIONAL);

        ScanExecutionResult result = ScanExecutionResult.completed(
                10L, 1L, "Target Site", 20, 20, List.of(f1, f2, f3), start, end
        );

        assertEquals(10L, result.getScanId());
        assertEquals(1L, result.getWebsiteId());
        assertEquals("Target Site", result.getWebsiteName());
        assertEquals(ScanStatus.COMPLETED, result.getFinalStatus());
        assertEquals(20, result.getPagesDiscovered());
        assertEquals(20, result.getPagesTested());
        assertEquals(3, result.getFindingsCount());
        assertEquals(1, result.getCriticalFindings());
        assertEquals(1, result.getHighFindings());
        assertEquals(0, result.getMediumFindings());
        assertEquals(0, result.getLowFindings());
        assertEquals(1, result.getInformationalFindings());
        assertTrue(result.getDuration().getSeconds() >= 14);
        assertNull(result.getErrorMessage());
    }

    @Test
    @DisplayName("ScanExecutionResult cancelled and failed factories populate metadata correctly")
    void testCancelledAndFailedFactories() {
        LocalDateTime start = LocalDateTime.now().minusSeconds(5);

        ScanExecutionResult cancelled = ScanExecutionResult.cancelled(11L, 1L, "Target", 10, 5, start);
        assertEquals(ScanStatus.CANCELLED, cancelled.getFinalStatus());
        assertNotNull(cancelled.getErrorMessage());

        ScanExecutionResult failed = ScanExecutionResult.failed(12L, 1L, "Target", "Connection timed out", start);
        assertEquals(ScanStatus.FAILED, failed.getFinalStatus());
        assertEquals("Connection timed out", failed.getErrorMessage());
    }

    @Test
    @DisplayName("ScanTask cooperatively marks cancellation flag")
    void testScanTaskCancellation() {
        ScanConfiguration config = new ScanConfiguration(1L, "Target", "https://example.com", 1);
        ScanProgressTracker tracker = new ScanProgressTracker();
        ScanTask task = new ScanTask(config, tracker, null, null, null, null);

        assertFalse(task.isCancelled());
        task.cancel();
        assertTrue(task.isCancelled());
    }
}
