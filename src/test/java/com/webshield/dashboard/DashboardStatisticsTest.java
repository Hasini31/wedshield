package com.webshield.dashboard;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("DashboardStatistics Tests")
class DashboardStatisticsTest {

    @Test
    @DisplayName("Empty statistics factory creates all zeros with 5 severity categories")
    void testEmptyStatistics() {
        DashboardStatistics stats = DashboardStatistics.empty();

        assertEquals(0, stats.getTotalWebsites(), "Total websites should be 0");
        assertEquals(0, stats.getTotalScans(), "Total scans should be 0");
        assertEquals(0, stats.getTotalFindings(), "Total findings should be 0");
        assertEquals(0, stats.getCriticalFindings(), "Critical findings should be 0");

        Map<String, Integer> bySeverity = stats.getFindingsBySeverity();
        assertNotNull(bySeverity);
        assertEquals(0, bySeverity.get("CRITICAL"));
        assertEquals(0, bySeverity.get("HIGH"));
        assertEquals(0, bySeverity.get("MEDIUM"));
        assertEquals(0, bySeverity.get("LOW"));
        assertEquals(0, bySeverity.get("INFORMATIONAL"));
    }

    @Test
    @DisplayName("Custom statistics properly hold provided database values")
    void testCustomStatistics() {
        Map<String, Integer> severityMap = Map.of(
                "CRITICAL", 2,
                "HIGH", 5,
                "MEDIUM", 8,
                "LOW", 12,
                "INFORMATIONAL", 3
        );
        DashboardStatistics stats = new DashboardStatistics(4, 10, 30, 2, severityMap);

        assertEquals(4, stats.getTotalWebsites());
        assertEquals(10, stats.getTotalScans());
        assertEquals(30, stats.getTotalFindings());
        assertEquals(2, stats.getCriticalFindings());
        assertEquals(2, stats.getFindingsBySeverity().get("CRITICAL"));
        assertEquals(5, stats.getFindingsBySeverity().get("HIGH"));
        assertEquals(8, stats.getFindingsBySeverity().get("MEDIUM"));
        assertEquals(12, stats.getFindingsBySeverity().get("LOW"));
        assertEquals(3, stats.getFindingsBySeverity().get("INFORMATIONAL"));
    }
}

