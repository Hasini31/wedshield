package com.webshield.dashboard;

import com.webshield.auth.SessionManager;
import com.webshield.models.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Service layer for dashboard data retrieval.
 *
 * <p>Enforces that the caller is authenticated and delegates all database
 * work to {@link DashboardRepository}.  The controller should call only
 * this class, never the repository directly.
 */
@Service
public class DashboardService {

    private static final Logger log = LoggerFactory.getLogger(DashboardService.class);
    private final DashboardRepository repo;

    public DashboardService() {
        this(new DashboardRepository());
    }

    public DashboardService(DashboardRepository repo) {
        this.repo = repo != null ? repo : new DashboardRepository();
    }

    /**
     * Loads aggregated statistics for the currently logged-in user.
     * Returns {@link DashboardStatistics#empty()} if no user is authenticated.
     */
    public DashboardStatistics getStatistics() {
        User user = SessionManager.getInstance().getCurrentUser();
        if (user == null) {
            log.warn("getStatistics called without authenticated user");
            return DashboardStatistics.empty();
        }
        return repo.loadStatistics(user.getId());
    }

    /**
     * Returns the 5 most recently registered websites for the current user.
     */
    public List<WebsiteRow> getRecentWebsites() {
        User user = SessionManager.getInstance().getCurrentUser();
        if (user == null) return List.of();
        return repo.loadRecentWebsites(user.getId());
    }

    /**
     * Returns the 5 most recent scans for the current user.
     */
    public List<ScanRow> getRecentScans() {
        User user = SessionManager.getInstance().getCurrentUser();
        if (user == null) return List.of();
        return repo.loadRecentScans(user.getId());
    }
}

