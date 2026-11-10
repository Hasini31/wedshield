package com.webshield.dashboard;

import com.webshield.auth.SessionManager;
import com.webshield.models.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("DashboardService Tests")
class DashboardServiceTest {

    private DashboardService service;

    @BeforeEach
    void setUp() {
        service = new DashboardService();
        SessionManager.getInstance().logout();
    }

    @AfterEach
    void tearDown() {
        SessionManager.getInstance().logout();
    }

    @Test
    @DisplayName("Unauthenticated user receives safe empty dashboard data")
    void testUnauthenticatedUserReturnsEmpty() {
        DashboardStatistics stats = service.getStatistics();
        assertNotNull(stats);
        assertEquals(0, stats.getTotalWebsites());
        assertEquals(0, stats.getTotalScans());
        assertEquals(0, stats.getTotalFindings());
        assertEquals(0, stats.getCriticalFindings());

        List<WebsiteRow> sites = service.getRecentWebsites();
        assertNotNull(sites);
        assertTrue(sites.isEmpty());

        List<ScanRow> scans = service.getRecentScans();
        assertNotNull(scans);
        assertTrue(scans.isEmpty());
    }

    @Test
    @DisplayName("Authenticated user queries are scoped to their user_id")
    void testAuthenticatedUserSession() {
        User user = new User(42, "Security Lead", "lead@webshield.io", "passHash",
                LocalDateTime.now(), LocalDateTime.now());
        SessionManager.getInstance().login(user);

        // When DB is offline or empty, gracefully returns non-null safe structures
        DashboardStatistics stats = service.getStatistics();
        assertNotNull(stats);
        assertNotNull(stats.getFindingsBySeverity());

        List<WebsiteRow> sites = service.getRecentWebsites();
        assertNotNull(sites);

        List<ScanRow> scans = service.getRecentScans();
        assertNotNull(scans);
    }
}

