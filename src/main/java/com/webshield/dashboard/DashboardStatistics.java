package com.webshield.dashboard;

import java.util.List;
import java.util.Map;

/**
 * Immutable snapshot of unified dashboard statistics for a single user.
 * Built by {@link DashboardRepository} and consumed by {@link DashboardService}
 * and {@link com.webshield.ui.controllers.DashboardController}.
 */
public class DashboardStatistics {

    // Card 1: Websites
    private final int totalWebsites;
    private final int activeWebsites;

    // Card 2: API Projects
    private final int totalApiProjects;

    // Card 3: Total Security Scans
    private final int totalWebsiteScans;
    private final int totalApiScans;
    private final int totalScans;

    // Card 4: API Test Cases Executed
    private final int apiTestCasesGenerated;
    private final int apiTestCasesExecuted;

    // Card 5: Total Vulnerabilities
    private final int totalWebsiteFindings;
    private final int totalApiFindings;
    private final int totalFindings;

    // Card 6: Critical Findings
    private final int criticalWebsiteFindings;
    private final int criticalApiFindings;
    private final int criticalFindings;

    // Section D Severity Breakdowns
    private final Map<String, Integer> websiteFindingsBySeverity;
    private final Map<String, Integer> apiFindingsBySeverity;
    private final Map<String, Integer> findingsBySeverity;

    // Section B Website Overview Metrics
    private final int websitesScanned;
    private final int totalPagesDiscovered;
    private final int totalPagesTested;
    private final String lastWebsiteScanDate;

    // Section C API Overview Metrics
    private final int totalApiEndpoints;
    private final List<ApiCategoryStat> apiCategoryStats;

    /**
     * Legacy 5-parameter constructor for backward compatibility.
     */
    public DashboardStatistics(int totalWebsites, int totalScans, int totalFindings,
                               int criticalFindings, Map<String, Integer> findingsBySeverity) {
        this(totalWebsites, 0, 0,
             totalScans, 0, totalScans,
             0, 0,
             totalFindings, 0, totalFindings,
             criticalFindings, 0, criticalFindings,
             findingsBySeverity, Map.of("CRITICAL", 0, "HIGH", 0, "MEDIUM", 0, "LOW", 0, "INFORMATIONAL", 0),
             findingsBySeverity,
             0, 0, 0, "—",
             0, List.of());
    }

    /**
     * Full constructor for Unified Security Command Center statistics.
     */
    public DashboardStatistics(int totalWebsites, int activeWebsites, int totalApiProjects,
                               int totalWebsiteScans, int totalApiScans, int totalScans,
                               int apiTestCasesGenerated, int apiTestCasesExecuted,
                               int totalWebsiteFindings, int totalApiFindings, int totalFindings,
                               int criticalWebsiteFindings, int criticalApiFindings, int criticalFindings,
                               Map<String, Integer> websiteFindingsBySeverity,
                               Map<String, Integer> apiFindingsBySeverity,
                               Map<String, Integer> findingsBySeverity,
                               int websitesScanned, int totalPagesDiscovered, int totalPagesTested,
                               String lastWebsiteScanDate, int totalApiEndpoints,
                               List<ApiCategoryStat> apiCategoryStats) {
        this.totalWebsites = totalWebsites;
        this.activeWebsites = activeWebsites;
        this.totalApiProjects = totalApiProjects;
        this.totalWebsiteScans = totalWebsiteScans;
        this.totalApiScans = totalApiScans;
        this.totalScans = totalScans;
        this.apiTestCasesGenerated = apiTestCasesGenerated;
        this.apiTestCasesExecuted = apiTestCasesExecuted;
        this.totalWebsiteFindings = totalWebsiteFindings;
        this.totalApiFindings = totalApiFindings;
        this.totalFindings = totalFindings;
        this.criticalWebsiteFindings = criticalWebsiteFindings;
        this.criticalApiFindings = criticalApiFindings;
        this.criticalFindings = criticalFindings;
        this.websiteFindingsBySeverity = websiteFindingsBySeverity != null ? websiteFindingsBySeverity : Map.of();
        this.apiFindingsBySeverity = apiFindingsBySeverity != null ? apiFindingsBySeverity : Map.of();
        this.findingsBySeverity = findingsBySeverity != null ? findingsBySeverity : Map.of();
        this.websitesScanned = websitesScanned;
        this.totalPagesDiscovered = totalPagesDiscovered;
        this.totalPagesTested = totalPagesTested;
        this.lastWebsiteScanDate = lastWebsiteScanDate != null ? lastWebsiteScanDate : "—";
        this.totalApiEndpoints = totalApiEndpoints;
        this.apiCategoryStats = apiCategoryStats != null ? apiCategoryStats : List.of();
    }

    /** Returns a zero-value statistics object (used when the DB has no data). */
    public static DashboardStatistics empty() {
        Map<String, Integer> emptySev = Map.of(
                "CRITICAL", 0, "HIGH", 0, "MEDIUM", 0, "LOW", 0, "INFORMATIONAL", 0);
        return new DashboardStatistics(
                0, 0, 0,
                0, 0, 0,
                0, 0,
                0, 0, 0,
                0, 0, 0,
                emptySev, emptySev, emptySev,
                0, 0, 0, "—",
                0, List.of()
        );
    }

    public int getTotalWebsites()              { return totalWebsites; }
    public int getActiveWebsites()             { return activeWebsites; }
    public int getTotalApiProjects()           { return totalApiProjects; }
    public int getTotalWebsiteScans()          { return totalWebsiteScans; }
    public int getTotalApiScans()              { return totalApiScans; }
    public int getTotalScans()                 { return totalScans; }
    public int getApiTestCasesGenerated()      { return apiTestCasesGenerated; }
    public int getApiTestCasesExecuted()       { return apiTestCasesExecuted; }
    public int getTotalWebsiteFindings()       { return totalWebsiteFindings; }
    public int getTotalApiFindings()           { return totalApiFindings; }
    public int getTotalFindings()              { return totalFindings; }
    public int getCriticalWebsiteFindings()    { return criticalWebsiteFindings; }
    public int getCriticalApiFindings()        { return criticalApiFindings; }
    public int getCriticalFindings()           { return criticalFindings; }
    public Map<String, Integer> getWebsiteFindingsBySeverity() { return websiteFindingsBySeverity; }
    public Map<String, Integer> getApiFindingsBySeverity()     { return apiFindingsBySeverity; }
    public Map<String, Integer> getFindingsBySeverity()        { return findingsBySeverity; }
    public int getWebsitesScanned()            { return websitesScanned; }
    public int getTotalPagesDiscovered()       { return totalPagesDiscovered; }
    public int getTotalPagesTested()           { return totalPagesTested; }
    public String getLastWebsiteScanDate()     { return lastWebsiteScanDate; }
    public int getTotalApiEndpoints()          { return totalApiEndpoints; }
    public List<ApiCategoryStat> getApiCategoryStats() { return apiCategoryStats; }
}
