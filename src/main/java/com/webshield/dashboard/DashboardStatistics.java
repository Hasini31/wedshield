package com.webshield.dashboard;

import java.util.Map;

/**
 * Immutable snapshot of dashboard statistics for a single user.
 * Built by {@link DashboardRepository} and consumed by {@link DashboardService}
 * and {@link com.webshield.ui.controllers.DashboardController}.
 */
public class DashboardStatistics {

    private final int totalWebsites;
    private final int totalScans;
    private final int totalFindings;
    private final int criticalFindings;

    /** Findings grouped by severity: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL */
    private final Map<String, Integer> findingsBySeverity;

    public DashboardStatistics(int totalWebsites, int totalScans, int totalFindings,
                               int criticalFindings, Map<String, Integer> findingsBySeverity) {
        this.totalWebsites      = totalWebsites;
        this.totalScans         = totalScans;
        this.totalFindings      = totalFindings;
        this.criticalFindings   = criticalFindings;
        this.findingsBySeverity = findingsBySeverity;
    }

    /** Returns a zero-value statistics object (used when the DB has no data). */
    public static DashboardStatistics empty() {
        return new DashboardStatistics(0, 0, 0, 0,
                Map.of("CRITICAL", 0, "HIGH", 0, "MEDIUM", 0, "LOW", 0, "INFORMATIONAL", 0));
    }

    public int getTotalWebsites()    { return totalWebsites;    }
    public int getTotalScans()       { return totalScans;        }
    public int getTotalFindings()    { return totalFindings;     }
    public int getCriticalFindings() { return criticalFindings;  }
    public Map<String, Integer> getFindingsBySeverity() { return findingsBySeverity; }
}

