package com.webshield.scan;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ScanProgressTracker Unit Tests")
class ScanProgressTrackerTest {

    @Test
    @DisplayName("Default state initializes cleanly")
    void testInitialState() {
        ScanProgressTracker tracker = new ScanProgressTracker();
        assertEquals(ScanStatus.PENDING, tracker.getStatus());
        assertEquals("Ready", tracker.getCurrentOperation());
        assertEquals(0, tracker.getPagesDiscovered());
        assertEquals(0, tracker.getPagesTested());
        assertEquals(0, tracker.getPagesRemaining());
        assertEquals(0, tracker.getChecksCompleted());
        assertEquals(0, tracker.getFindingsGenerated());
        assertEquals(0.0, tracker.getProgressPercentage());
        assertNull(tracker.getStartTime());
        assertNull(tracker.getCompletionTime());
    }

    @Test
    @DisplayName("start() transitions status to INITIALIZING and records timestamp")
    void testStart() {
        ScanProgressTracker tracker = new ScanProgressTracker();
        tracker.start();

        assertEquals(ScanStatus.INITIALIZING, tracker.getStatus());
        assertNotNull(tracker.getStartTime());
    }

    @Test
    @DisplayName("Progress percentage calculates accurately across testing milestones")
    void testProgressCalculation() {
        ScanProgressTracker tracker = new ScanProgressTracker();
        tracker.setPagesDiscovered(100);
        assertEquals(0.0, tracker.getProgressPercentage(), 0.001);

        tracker.setPagesTested(25);
        assertEquals(0.25, tracker.getProgressPercentage(), 0.001);
        assertEquals(75, tracker.getPagesRemaining());

        tracker.setPagesTested(100);
        assertEquals(1.0, tracker.getProgressPercentage(), 0.001);
        assertEquals(0, tracker.getPagesRemaining());
    }

    @Test
    @DisplayName("Progress percentage caps at 1.0 even if tested exceeds discovered")
    void testProgressPercentageCapping() {
        ScanProgressTracker tracker = new ScanProgressTracker();
        tracker.setPagesDiscovered(5);
        tracker.setPagesTested(10);
        assertEquals(1.0, tracker.getProgressPercentage(), 0.001);
        assertEquals(0, tracker.getPagesRemaining());
    }

    @Test
    @DisplayName("Counters increment correctly")
    void testCounterIncrements() {
        ScanProgressTracker tracker = new ScanProgressTracker();
        tracker.incrementPagesDiscovered();
        tracker.addPagesDiscovered(4);
        assertEquals(5, tracker.getPagesDiscovered());

        tracker.incrementPagesTested();
        assertEquals(1, tracker.getPagesTested());

        tracker.incrementChecksCompleted(10);
        assertEquals(10, tracker.getChecksCompleted());

        tracker.incrementFindingsGenerated();
        tracker.addFindingsGenerated(2);
        assertEquals(3, tracker.getFindingsGenerated());
    }

    @Test
    @DisplayName("Listeners receive notifications upon state updates")
    void testListenerNotification() {
        ScanProgressTracker tracker = new ScanProgressTracker();
        AtomicInteger notificationCount = new AtomicInteger(0);

        tracker.addListener(t -> notificationCount.incrementAndGet());

        tracker.setStatus(ScanStatus.CRAWLING);
        tracker.setOperation("Auditing /api");
        tracker.setPagesDiscovered(10);

        assertTrue(notificationCount.get() >= 3);
    }

    @Test
    @DisplayName("Terminal statuses record completion time")
    void testTerminalStatusCompletion() {
        ScanProgressTracker tracker = new ScanProgressTracker();
        tracker.start();
        tracker.setStatus(ScanStatus.COMPLETED);

        assertNotNull(tracker.getCompletionTime());
        assertTrue(tracker.getElapsedTime().toMillis() >= 0);
    }
}

