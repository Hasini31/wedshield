package com.webshield.ui.controllers;

import com.webshield.auth.AuthService;
import com.webshield.auth.SessionManager;
import com.webshield.models.User;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * ShellController manages the primary application window.
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>Navigation: updates sidebar active state and top-bar title / breadcrumb.</li>
 *   <li>Page loading: lazy-loads each page FXML on first visit and caches it.</li>
 *   <li>Content switching: swaps the visible child of the centre {@link StackPane}.</li>
 *   <li>Session: shows the current user's name/initials and handles logout.</li>
 * </ul>
 */
@Component
@Scope("prototype")
public class ShellController {

    private static final Logger log = LoggerFactory.getLogger(ShellController.class);

    /* ── FXML injections ──────────────────────────────────────────── */

    @FXML private StackPane contentArea;
    @FXML private Label     lblPageTitle;
    @FXML private Label     lblBreadcrumb;

    @FXML private Button    navDashboard;
    @FXML private Button    navWebsites;
    @FXML private Button    navScans;
    @FXML private Button    navHistory;
    @FXML private Button    navReports;
    @FXML private Button    navApiTesting;
    @FXML private Button    navApiProjects;
    @FXML private Button    navApiConfig;
    @FXML private Button    navApiScan;
    @FXML private Button    navApiTestCases;
    @FXML private Button    navApiExecutions;
    @FXML private Button    navApiFindings;
    @FXML private Button    navApiHistory;
    @FXML private Button    navApiComparison;
    @FXML private Button    navApiReports;
    @FXML private Button    navSettings;

    // Top-bar user display (optional – only set if FXML has fx:id)
    @FXML private Label     lblUserName;
    @FXML private Label     lblUserInitials;

    /* ── Page cache ─────────────────────────────────────────────── */

    private final Map<String, Node> pageCache = new HashMap<>();
    private Button activeNavButton;
    private final AuthService authService;
    private static ShellController instance;

    public ShellController() {
        this(com.webshield.config.SpringContext.getBean(AuthService.class));
    }

    public ShellController(AuthService authService) {
        this.authService = authService != null ? authService : new AuthService();
    }

    /* ── Lifecycle ──────────────────────────────────────────────── */

    public static ShellController getInstance() {
        return instance;
    }

    @FXML
    public void initialize() {
        instance = this;
        log.info("ShellController initialised");
        populateUserDisplay();
        navigateTo("dashboard", navDashboard, "Dashboard", "Overview");
    }

    public void reloadCurrentPage() {
        if (activeNavButton == navDashboard) onNavDashboard();
        else if (activeNavButton == navWebsites) onNavWebsites();
        else if (activeNavButton == navScans) onNavScans();
        else if (activeNavButton == navHistory) onNavHistory();
        else if (activeNavButton == navReports) onNavReports();
        else if (activeNavButton == navApiTesting) onNavApiTesting();
    }

    public void clearCache(String pageKey) {
        pageCache.remove(pageKey);
    }

    public void openWebsites() {
        pageCache.remove("websites");
        onNavWebsites();
    }

    public void openWebsiteDetails(long websiteId) {
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource("/fxml/pages/website_details.fxml"));
            Node node = loader.load();
            WebsiteDetailsController controller = loader.getController();
            controller.loadWebsite(websiteId);

            if (lblPageTitle != null) lblPageTitle.setText("Website Details");
            if (lblBreadcrumb != null) lblBreadcrumb.setText("Target Management / Details");

            contentArea.getChildren().clear();
            contentArea.getChildren().add(node);
        } catch (IOException e) {
            log.error("Failed to load website details page", e);
        }
    }

    public void openSecurityScansFor(Long websiteId) {
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource("/fxml/pages/security_scans.fxml"));
            Node node = loader.load();
            SecurityScansController controller = loader.getController();
            if (websiteId != null) {
                controller.selectWebsite(websiteId);
            }
            setActiveNavButton(navScans);
            if (lblPageTitle != null) lblPageTitle.setText("Security Scans");
            if (lblBreadcrumb != null) lblBreadcrumb.setText("Assessment Console");

            contentArea.getChildren().clear();
            contentArea.getChildren().add(node);
        } catch (IOException e) {
            log.error("Failed to load security scans page", e);
        }
    }

    public void openReportsForScan(long scanId) {
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource("/fxml/pages/reports.fxml"));
            Node node = loader.load();
            ReportsController controller = loader.getController();
            controller.filterByScanId(scanId);
            setActiveNavButton(navReports);
            if (lblPageTitle != null) lblPageTitle.setText("Reports");
            if (lblBreadcrumb != null) lblBreadcrumb.setText("Findings & Vulnerabilities / Scan #" + scanId);

            contentArea.getChildren().clear();
            contentArea.getChildren().add(node);
        } catch (IOException e) {
            log.error("Failed to load reports page for scan id=" + scanId, e);
        }
    }

    public void openApiProjects() {
        pageCache.remove("api_projects");
        onNavApiProjects();
    }

    public void openApiProjectDetails(Long projectId) {
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource("/fxml/pages/api_project_details.fxml"));
            Node node = loader.load();
            ApiProjectDetailsController controller = loader.getController();
            controller.loadProject(projectId);

            if (lblPageTitle != null) lblPageTitle.setText("API Project Details");
            if (lblBreadcrumb != null) lblBreadcrumb.setText("Project Management / Specification");

            contentArea.getChildren().clear();
            contentArea.getChildren().add(node);
        } catch (IOException e) {
            log.error("Failed to load API project details page", e);
        }
    }

    public void openApiTestConfigFor(Long projectId) {
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource("/fxml/pages/api_test_config.fxml"));
            Node node = loader.load();
            ApiTestConfigController controller = loader.getController();
            if (projectId != null) {
                controller.setPreselectedProjectId(projectId);
            }
            setActiveNavButton(navApiConfig != null ? navApiConfig : navApiProjects);
            if (lblPageTitle != null) lblPageTitle.setText("Test Configuration");
            if (lblBreadcrumb != null) lblBreadcrumb.setText("Scan Scope & Parameters");

            contentArea.getChildren().clear();
            contentArea.getChildren().add(node);
        } catch (IOException e) {
            log.error("Failed to load API test config page", e);
        }
    }

    public void openApiScanFor(Long projectId) {
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource("/fxml/pages/api_scan_execution.fxml"));
            Node node = loader.load();
            ApiScanExecutionController controller = loader.getController();
            if (projectId != null) {
                controller.setPreselectedProjectId(projectId);
            }
            setActiveNavButton(navApiScan != null ? navApiScan : navApiProjects);
            if (lblPageTitle != null) lblPageTitle.setText("Scan Execution");
            if (lblBreadcrumb != null) lblBreadcrumb.setText("Live Assessment Console");

            contentArea.getChildren().clear();
            contentArea.getChildren().add(node);
        } catch (IOException e) {
            log.error("Failed to load API scan execution page", e);
        }
    }

    public void openApiTestCasesForScan(Long scanId) {
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource("/fxml/pages/api_test_cases.fxml"));
            Node node = loader.load();
            ApiTestCasesController controller = loader.getController();
            if (scanId != null) {
                controller.setPreselectedScanId(scanId);
            }
            setActiveNavButton(navApiTestCases != null ? navApiTestCases : navApiProjects);
            if (lblPageTitle != null) lblPageTitle.setText("Test Cases");
            if (lblBreadcrumb != null) lblBreadcrumb.setText("Lineage & Categories / Scan #" + scanId);

            contentArea.getChildren().clear();
            contentArea.getChildren().add(node);
        } catch (IOException e) {
            log.error("Failed to load API test cases page", e);
        }
    }

    public void openApiExecutionsForScan(Long scanId) {
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource("/fxml/pages/api_execution_results.fxml"));
            Node node = loader.load();
            ApiExecutionResultsController controller = loader.getController();
            if (scanId != null) {
                controller.setPreselectedScanId(scanId);
            }
            setActiveNavButton(navApiExecutions != null ? navApiExecutions : navApiProjects);
            if (lblPageTitle != null) lblPageTitle.setText("Execution Results");
            if (lblBreadcrumb != null) lblBreadcrumb.setText("HTTP Traffic Logs / Scan #" + scanId);

            contentArea.getChildren().clear();
            contentArea.getChildren().add(node);
        } catch (IOException e) {
            log.error("Failed to load API executions page", e);
        }
    }

    public void openApiFindingsForScan(Long scanId) {
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource("/fxml/pages/api_security_findings.fxml"));
            Node node = loader.load();
            ApiSecurityFindingsController controller = loader.getController();
            if (scanId != null) {
                controller.setPreselectedScanId(scanId);
            }
            setActiveNavButton(navApiFindings != null ? navApiFindings : navApiProjects);
            if (lblPageTitle != null) lblPageTitle.setText("Security Findings");
            if (lblBreadcrumb != null) lblBreadcrumb.setText("Vulnerabilities & OWASP Top 10 / Scan #" + scanId);

            contentArea.getChildren().clear();
            contentArea.getChildren().add(node);
        } catch (IOException e) {
            log.error("Failed to load API findings page", e);
        }
    }

    public void openApiComparisonFor(Long scanAId, Long scanBId) {
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource("/fxml/pages/api_scan_comparison.fxml"));
            Node node = loader.load();
            ApiScanComparisonController controller = loader.getController();
            if (scanAId != null || scanBId != null) {
                controller.setPreselectedScans(scanAId, scanBId);
            }
            setActiveNavButton(navApiComparison != null ? navApiComparison : navApiProjects);
            if (lblPageTitle != null) lblPageTitle.setText("Scan Comparison");
            if (lblBreadcrumb != null) lblBreadcrumb.setText("Differential & Regression Analysis");

            contentArea.getChildren().clear();
            contentArea.getChildren().add(node);
        } catch (IOException e) {
            log.error("Failed to load API scan comparison page", e);
        }
    }

    public void openApiReportsForScan(Long scanId) {
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource("/fxml/pages/api_reports.fxml"));
            Node node = loader.load();
            ApiReportsController controller = loader.getController();
            if (scanId != null) {
                controller.setPreselectedScanId(scanId);
            }
            setActiveNavButton(navApiReports != null ? navApiReports : navApiProjects);
            if (lblPageTitle != null) lblPageTitle.setText("API Security Reports");
            if (lblBreadcrumb != null) lblBreadcrumb.setText("Vulnerability Reports & AI Insights / Scan #" + scanId);

            contentArea.getChildren().clear();
            contentArea.getChildren().add(node);
        } catch (IOException e) {
            log.error("Failed to load API reports page", e);
        }
    }

    /* ── Navigation handlers ────────────────────────────────────── */

    @FXML private void onNavDashboard() {
        pageCache.remove("dashboard");
        navigateTo("dashboard",      navDashboard, "Dashboard",      "Overview");
    }
    @FXML private void onNavWebsites() {
        pageCache.remove("websites");
        navigateTo("websites",       navWebsites,  "Websites",       "Target Management");
    }
    @FXML private void onNavScans() {
        pageCache.remove("security_scans");
        navigateTo("security_scans", navScans,     "Security Scans", "Assessment Console");
    }
    @FXML private void onNavHistory() {
        pageCache.remove("scan_history");
        navigateTo("scan_history",   navHistory,   "Scan History",   "Assessment Log");
    }
    @FXML private void onNavReports() {
        pageCache.remove("reports");
        navigateTo("reports",        navReports,   "Reports",        "Findings & Vulnerabilities");
    }
    @FXML private void onNavApiTesting() {
        onNavApiProjects();
    }
    @FXML private void onNavApiProjects() {
        pageCache.remove("api_projects");
        navigateTo("api_projects",   navApiProjects != null ? navApiProjects : navApiTesting, "API Security Testing", "Project Management");
    }
    @FXML private void onNavApiConfig() {
        pageCache.remove("api_test_config");
        navigateTo("api_test_config", navApiConfig, "Test Configuration", "Scan Scope & Parameters");
    }
    @FXML private void onNavApiScan() {
        pageCache.remove("api_scan_execution");
        navigateTo("api_scan_execution", navApiScan, "Scan Execution", "Live Assessment Console");
    }
    @FXML private void onNavApiTestCases() {
        pageCache.remove("api_test_cases");
        navigateTo("api_test_cases", navApiTestCases, "Test Cases", "Lineage & Categories");
    }
    @FXML private void onNavApiExecutions() {
        pageCache.remove("api_execution_results");
        navigateTo("api_execution_results", navApiExecutions, "Execution Results", "HTTP Traffic Logs");
    }
    @FXML private void onNavApiFindings() {
        pageCache.remove("api_security_findings");
        navigateTo("api_security_findings", navApiFindings, "Security Findings", "Vulnerabilities & OWASP Top 10");
    }
    @FXML private void onNavApiHistory() {
        pageCache.remove("api_scan_history");
        navigateTo("api_scan_history", navApiHistory, "API Scan History", "Historical Runs & Metrics");
    }
    @FXML private void onNavApiComparison() {
        pageCache.remove("api_scan_comparison");
        navigateTo("api_scan_comparison", navApiComparison, "Scan Comparison", "Differential & Regression Analysis");
    }
    @FXML private void onNavApiReports() {
        pageCache.remove("api_reports");
        navigateTo("api_reports",    navApiReports != null ? navApiReports : navReports, "API Security Reports", "Executive Reports & AI Insights");
    }
    @FXML private void onNavSettings() {
        navigateTo("settings",       navSettings,  "Settings",       "Configuration");
    }

    /** Log out the current session and return to the Login screen. */
    @FXML
    private void onLogout(ActionEvent event) {
        authService.logout();
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource("/fxml/pages/login.fxml"));
            Parent root = loader.load();
            Scene scene = new Scene(root, 820, 620);
            URL cssUrl = getClass().getResource("/css/styles.css");
            if (cssUrl != null) scene.getStylesheets().add(cssUrl.toExternalForm());
            Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
            stage.setScene(scene);
            stage.setTitle("WebShield – Sign In");
            log.info("User logged out – returned to login screen");
        } catch (IOException e) {
            log.error("Failed to load login screen after logout", e);
        }
    }

    /* ── Core navigation logic ─────────────────────────────────── */

    private void navigateTo(String pageKey, Button navButton, String title, String crumb) {
        if (lblPageTitle  != null) lblPageTitle.setText(title);
        if (lblBreadcrumb != null) lblBreadcrumb.setText(crumb);
        setActiveNavButton(navButton);

        Node page = pageCache.computeIfAbsent(pageKey, this::loadPage);
        if (page == null) {
            log.error("Failed to load page: {}", pageKey);
            return;
        }
        contentArea.getChildren().clear();
        contentArea.getChildren().add(page);
    }

    private Node loadPage(String pageKey) {
        String fxmlPath = "/fxml/pages/" + pageKey + ".fxml";
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource(fxmlPath));
            Node node = loader.load();
            log.debug("Loaded page: {}", fxmlPath);
            return node;
        } catch (IOException e) {
            log.error("Could not load FXML: {}", fxmlPath, e);
            return null;
        }
    }

    private void setActiveNavButton(Button button) {
        if (activeNavButton != null) {
            activeNavButton.getStyleClass().remove("ws-nav-btn-active");
        }
        activeNavButton = button;
        if (button != null && !button.getStyleClass().contains("ws-nav-btn-active")) {
            button.getStyleClass().add("ws-nav-btn-active");
        }
    }

    /* ── User display ───────────────────────────────────────────── */

    private void populateUserDisplay() {
        User user = SessionManager.getInstance().getCurrentUser();
        if (user == null) return;
        if (lblUserName != null) {
            lblUserName.setText(user.getFullName());
        }
        if (lblUserInitials != null) {
            lblUserInitials.setText(initials(user.getFullName()));
        }
    }

    private static String initials(String fullName) {
        if (fullName == null || fullName.isBlank()) return "U";
        String[] parts = fullName.trim().split("\\s+");
        if (parts.length == 1) return parts[0].substring(0, 1).toUpperCase();
        return (parts[0].charAt(0) + "" + parts[parts.length - 1].charAt(0)).toUpperCase();
    }
}
