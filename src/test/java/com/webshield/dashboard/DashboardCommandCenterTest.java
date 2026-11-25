package com.webshield.dashboard;

import com.webshield.auth.SessionManager;
import com.webshield.models.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Dashboard Command Center Telemetry & Model Tests")
class DashboardCommandCenterTest {

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
    @DisplayName("Verify DashboardStatistics constructor preserves all metrics across Website & API engines")
    void testDashboardStatisticsComprehensive() {
        Map<String, Integer> webSev = Map.of("CRITICAL", 2, "HIGH", 4, "MEDIUM", 6, "LOW", 8, "INFORMATIONAL", 1);
        Map<String, Integer> apiSev = Map.of("CRITICAL", 3, "HIGH", 5, "MEDIUM", 7, "LOW", 9, "INFORMATIONAL", 2);
        Map<String, Integer> combinedSev = Map.of("CRITICAL", 5, "HIGH", 9, "MEDIUM", 13, "LOW", 17, "INFORMATIONAL", 3);

        List<ApiCategoryStat> catStats = List.of(
                new ApiCategoryStat("VALID_SMOKE", 10, 10, 0),
                new ApiCategoryStat("BOUNDARY", 25, 24, 2),
                new ApiCategoryStat("MISSING_REQUIRED", 15, 15, 1),
                new ApiCategoryStat("TYPE_CONFUSION", 12, 12, 1),
                new ApiCategoryStat("SECURITY_PROBES", 20, 20, 4)
        );

        DashboardStatistics stats = new DashboardStatistics(
                8, 6, 3,
                12, 5, 17,
                82, 81,
                21, 29, 50,
                2, 3, 5,
                webSev, apiSev, combinedSev,
                5, 140, 115,
                "11 Nov 2026 19:30", 24, catStats
        );

        assertEquals(8, stats.getTotalWebsites());
        assertEquals(6, stats.getActiveWebsites());
        assertEquals(3, stats.getTotalApiProjects());
        assertEquals(12, stats.getTotalWebsiteScans());
        assertEquals(5, stats.getTotalApiScans());
        assertEquals(17, stats.getTotalScans());
        assertEquals(82, stats.getApiTestCasesGenerated());
        assertEquals(81, stats.getApiTestCasesExecuted());
        assertEquals(21, stats.getTotalWebsiteFindings());
        assertEquals(29, stats.getTotalApiFindings());
        assertEquals(50, stats.getTotalFindings());
        assertEquals(2, stats.getCriticalWebsiteFindings());
        assertEquals(3, stats.getCriticalApiFindings());
        assertEquals(5, stats.getCriticalFindings());
        assertEquals(5, stats.getWebsitesScanned());
        assertEquals(140, stats.getTotalPagesDiscovered());
        assertEquals(115, stats.getTotalPagesTested());
        assertEquals("11 Nov 2026 19:30", stats.getLastWebsiteScanDate());
        assertEquals(24, stats.getTotalApiEndpoints());
        assertEquals(5, stats.getApiCategoryStats().size());
    }

    @Test
    @DisplayName("Verify Unauthenticated user receives non-null safe empty collections for all command center tables")
    void testUnauthenticatedUserSafety() {
        assertNotNull(service.getStatistics());
        assertTrue(service.getWebsiteOverview().isEmpty());
        assertTrue(service.getRecentSecurityActivity().isEmpty());
        assertTrue(service.getCriticalFindings().isEmpty());
        assertTrue(service.getRecentWebsites().isEmpty());
        assertTrue(service.getRecentScans().isEmpty());
        assertTrue(service.getApiProjectOverview().isEmpty());
    }

    @Test
    @DisplayName("Verify Authenticated user queries return non-null collections even under DB fault")
    void testAuthenticatedUserRobustness() {
        User user = new User(99, "Security Operator", "operator@webshield.io", "hash",
                LocalDateTime.now(), LocalDateTime.now());
        SessionManager.getInstance().login(user);

        DashboardStatistics stats = service.getStatistics();
        assertNotNull(stats);
        assertNotNull(stats.getWebsiteFindingsBySeverity());
        assertNotNull(stats.getApiFindingsBySeverity());
        assertNotNull(stats.getFindingsBySeverity());
        assertNotNull(stats.getApiCategoryStats());

        List<WebsiteOverviewRow> overview = service.getWebsiteOverview();
        assertNotNull(overview);

        List<ApiProjectOverviewRow> apiOverview = service.getApiProjectOverview();
        assertNotNull(apiOverview);

        List<SecurityActivityRow> activities = service.getRecentSecurityActivity();
        assertNotNull(activities);

        List<CriticalFindingRow> criticals = service.getCriticalFindings();
        assertNotNull(criticals);
    }

    @Test
    @DisplayName("Verify Row DTO models encapsulate all table columns correctly")
    void testRowModels() {
        WebsiteOverviewRow web = new WebsiteOverviewRow(1L, "Target Site", "http://target.com", 20, 18, 5, 1, 2, "10 Nov 2026 12:00", "COMPLETED", 101L);
        assertEquals(1L, web.getId());
        assertEquals("Target Site", web.getName());
        assertEquals("http://target.com", web.getUrl());
        assertEquals(20, web.getPagesDiscovered());
        assertEquals(18, web.getPagesTested());
        assertEquals(5, web.getTotalFindings());
        assertEquals(1, web.getCriticalFindings());
        assertEquals(2, web.getHighFindings());
        assertEquals("10 Nov 2026 12:00", web.getLastScan());
        assertEquals("COMPLETED", web.getScanStatus());
        assertEquals(101L, web.getLastScanId());

        ApiProjectOverviewRow apiRow = new ApiProjectOverviewRow(5L, "Swagger Petstore", "OPENAPI_3 (JSON)", 14, 3, 45, 120, 10, 1, 2, 3, 2, 2, "15 Nov 2026 14:00", "COMPLETED", 55L);
        assertEquals(5L, apiRow.getId());
        assertEquals("Swagger Petstore", apiRow.getName());
        assertEquals("OPENAPI_3 (JSON)", apiRow.getSpecDisplay());
        assertEquals(14, apiRow.getEndpointsCount());
        assertEquals(3, apiRow.getScansRun());
        assertEquals(45, apiRow.getTestCasesGenerated());
        assertEquals(120, apiRow.getRequestsExecuted());
        assertEquals(10, apiRow.getTotalFindings());
        assertEquals(1, apiRow.getCriticalFindings());
        assertEquals(2, apiRow.getHighFindings());
        assertEquals(3, apiRow.getMediumFindings());
        assertEquals(2, apiRow.getLowFindings());
        assertEquals(2, apiRow.getInfoFindings());
        assertEquals("15 Nov 2026 14:00", apiRow.getLastScanDate());
        assertEquals("COMPLETED", apiRow.getStatus());
        assertEquals(55L, apiRow.getLastScanId());
        assertEquals(1, apiRow.getFindingsBySeverity().get("CRITICAL"));
        assertEquals(2, web.getHighFindings());
        assertEquals("10 Nov 2026 12:00", web.getLastScan());
        assertEquals("COMPLETED", web.getScanStatus());
        assertEquals(101L, web.getLastScanId());

        SecurityActivityRow act = new SecurityActivityRow(202L, "API-#202", "Pet Store API", "API", "11 Nov 2026 14:00", "1.2s", "129 reqs", 29, "COMPLETED");
        assertEquals(202L, act.getRawScanId());
        assertEquals("API-#202", act.getDisplayId());
        assertEquals("Pet Store API", act.getTargetName());
        assertEquals("API", act.getTargetType());
        assertEquals("1.2s", act.getDuration());
        assertEquals("129 reqs", act.getUnitsTested());
        assertEquals(29, act.getFindingsCount());
        assertEquals("COMPLETED", act.getScanStatus());

        CriticalFindingRow crit = new CriticalFindingRow(303L, "SQL Injection Detected", "/api/v1/coupons/validate", "API", "Injection", "CRITICAL", "CONFIRMED", "ACTIVE", 202L);
        assertEquals(303L, crit.getFindingId());
        assertEquals("SQL Injection Detected", crit.getFindingName());
        assertEquals("/api/v1/coupons/validate", crit.getTarget());
        assertEquals("API", crit.getTargetType());
        assertEquals("Injection", crit.getCategory());
        assertEquals("CRITICAL", crit.getSeverity());
        assertEquals("CONFIRMED", crit.getConfidence());
        assertEquals("ACTIVE", crit.getReviewStatus());
        assertEquals(202L, crit.getScanId());
    }
}

