package com.webshield.ui.controllers;

import com.webshield.auth.SessionManager;
import com.webshield.dashboard.*;
import com.webshield.models.User;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.chart.*;
import javafx.scene.control.*;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * DashboardController populates all dashboard widgets from MySQL via
 * {@link DashboardService}.  Data is loaded on a background thread so
 * the UI thread is never blocked.
 */
@Component
@Scope("prototype")
public class DashboardController {

    private static final Logger log = LoggerFactory.getLogger(DashboardController.class);

    /* ── overview cards ────────────────────────────────────────────── */
    @FXML private Label statTargets;
    @FXML private Label statScans;
    @FXML private Label statFindings;
    @FXML private Label statCritical;

    /* ── API testing overview cards ────────────────────────────────── */
    @FXML private Label statApiProjects;
    @FXML private Label statApiScans;
    @FXML private Label statApiFindings;

    /* ── severity chart ────────────────────────────────────────────── */
    @FXML private BarChart<String, Number>        severityChart;
    @FXML private CategoryAxis                    severityXAxis;
    @FXML private NumberAxis                      severityYAxis;
    @FXML private StackPane                       chartEmptyState;

    /* ── recent websites table ─────────────────────────────────────── */
    @FXML private TableView<WebsiteRow>           websitesTable;
    @FXML private TableColumn<WebsiteRow, String> colSiteName;
    @FXML private TableColumn<WebsiteRow, String> colSiteUrl;
    @FXML private TableColumn<WebsiteRow, String> colSiteAdded;
    @FXML private TableColumn<WebsiteRow, String> colSiteLastScan;
    @FXML private TableColumn<WebsiteRow, String> colSiteStatus;
    @FXML private VBox                            websitesEmptyState;

    /* ── recent scans table ────────────────────────────────────────── */
    @FXML private TableView<ScanRow>              scansTable;
    @FXML private TableColumn<ScanRow, String>    colScanSite;
    @FXML private TableColumn<ScanRow, String>    colScanDate;
    @FXML private TableColumn<ScanRow, String>    colScanStatus;
    @FXML private TableColumn<ScanRow, String>    colScanFindings;
    @FXML private VBox                            scansEmptyState;

    private final DashboardService service;

    public DashboardController() {
        this(com.webshield.config.SpringContext.getBean(DashboardService.class));
    }

    public DashboardController(DashboardService service) {
        this.service = service != null ? service : new DashboardService();
    }

    /* ── lifecycle ─────────────────────────────────────────────────── */

    @FXML
    public void initialize() {
        configureTables();
        loadDataAsync();
    }

    /* ── table column wiring ───────────────────────────────────────── */

    private void configureTables() {
        colSiteName.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().getName()));
        colSiteUrl.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().getUrl()));
        colSiteAdded.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().getRegisteredAt()));
        colSiteLastScan.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().getLastScan()));
        colSiteStatus.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().getStatus()));

        colScanSite.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().getWebsiteName()));
        colScanDate.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().getStartedAt()));
        colScanStatus.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().getStatus()));
        colScanFindings.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(
                        String.valueOf(data.getValue().getFindingsCount())));

        websitesTable.setPlaceholder(new Label(""));
        scansTable.setPlaceholder(new Label(""));
    }

    /* ── async data loading ────────────────────────────────────────── */

    private void loadDataAsync() {
        Task<Void> task = new Task<>() {
            DashboardStatistics stats;
            List<WebsiteRow>    sites;
            List<ScanRow>       scans;
            int apiProjectsCount = 0;
            int apiScansCount = 0;
            int apiFindingsCount = 0;

            @Override
            protected Void call() {
                stats = service.getStatistics();
                sites = service.getRecentWebsites();
                scans = service.getRecentScans();

                try {
                    User currentUser = SessionManager.getInstance().getCurrentUser();
                    Long uid = currentUser != null ? (long) currentUser.getId() : null;
                    if (uid != null) {
                        com.webshield.api.service.ApiProjectService projSvc = com.webshield.config.SpringContext.getBean(com.webshield.api.service.ApiProjectService.class);
                        if (projSvc != null) {
                            apiProjectsCount = projSvc.getProjectsForCurrentUser().size();
                        }
                        com.webshield.api.service.ApiPersistenceService persistSvc = com.webshield.config.SpringContext.getBean(com.webshield.api.service.ApiPersistenceService.class);
                        if (persistSvc != null) {
                            var userScans = persistSvc.getScansForUser(uid);
                            apiScansCount = userScans.size();
                            apiFindingsCount = userScans.stream().mapToInt(com.webshield.api.dto.ApiScanDto::totalFindings).sum();
                        }
                    }
                } catch (Exception e) {
                    log.debug("API testing metrics not loaded: {}", e.getMessage());
                }

                return null;
            }

            @Override
            protected void succeeded() {
                Platform.runLater(() -> {
                    populateUI(stats, sites, scans);
                    populateApiStats(apiProjectsCount, apiScansCount, apiFindingsCount);
                });
            }

            @Override
            protected void failed() {
                log.error("Dashboard data load failed", getException());
                Platform.runLater(() -> populateUI(
                        DashboardStatistics.empty(), List.of(), List.of()));
            }
        };

        Thread t = new Thread(task, "dashboard-load");
        t.setDaemon(true);
        t.start();
    }

    private void populateApiStats(int projects, int scans, int findings) {
        if (statApiProjects != null) statApiProjects.setText(String.valueOf(projects));
        if (statApiScans != null) statApiScans.setText(String.valueOf(scans));
        if (statApiFindings != null) statApiFindings.setText(String.valueOf(findings));
    }

    @FXML
    private void onOpenApiTesting() {
        if (ShellController.getInstance() != null) {
            ShellController.getInstance().openApiProjects();
        }
    }

    /* ── populate UI from data ─────────────────────────────────────── */

    private void populateUI(DashboardStatistics stats,
                             List<WebsiteRow> sites,
                             List<ScanRow> scans) {
        // Stat cards
        statTargets.setText(String.valueOf(stats.getTotalWebsites()));
        statScans.setText(String.valueOf(stats.getTotalScans()));
        statFindings.setText(String.valueOf(stats.getTotalFindings()));
        statCritical.setText(String.valueOf(stats.getCriticalFindings()));

        // Severity bar chart
        populateChart(stats.getFindingsBySeverity());

        // Update user initials in topbar
        updateUserDisplay();

        // Recent websites
        ObservableList<WebsiteRow> siteList = FXCollections.observableArrayList(sites);
        websitesTable.setItems(siteList);
        boolean noSites = sites.isEmpty();
        websitesTable.setVisible(!noSites);
        websitesTable.setManaged(!noSites);
        if (websitesEmptyState != null) {
            websitesEmptyState.setVisible(noSites);
            websitesEmptyState.setManaged(noSites);
        }

        // Recent scans
        ObservableList<ScanRow> scanList = FXCollections.observableArrayList(scans);
        scansTable.setItems(scanList);
        boolean noScans = scans.isEmpty();
        scansTable.setVisible(!noScans);
        scansTable.setManaged(!noScans);
        if (scansEmptyState != null) {
            scansEmptyState.setVisible(noScans);
            scansEmptyState.setManaged(noScans);
        }
    }

    private void populateChart(Map<String, Integer> bySeverity) {
        boolean hasData = bySeverity.values().stream().anyMatch(v -> v > 0);

        if (chartEmptyState != null) {
            chartEmptyState.setVisible(!hasData);
            chartEmptyState.setManaged(!hasData);
        }
        if (severityChart != null) {
            severityChart.setVisible(hasData);
            severityChart.setManaged(hasData);
        }

        if (!hasData || severityChart == null) return;

        XYChart.Series<String, Number> series = new XYChart.Series<>();
        series.setName("Findings");

        for (Map.Entry<String, Integer> entry : bySeverity.entrySet()) {
            series.getData().add(new XYChart.Data<>(
                    capitalise(entry.getKey()), entry.getValue()));
        }

        severityChart.getData().clear();
        severityChart.getData().add(series);
    }

    private void updateUserDisplay() {
        // Retrieve the logged-in user's initials so the topbar shows real data.
        // The topbar is owned by ShellController, so we just log here.
        User user = SessionManager.getInstance().getCurrentUser();
        if (user != null) {
            log.debug("Dashboard loaded for user: {}", user.getEmail());
        }
    }

    private static String capitalise(String s) {
        if (s == null || s.isEmpty()) return s;
        return s.charAt(0) + s.substring(1).toLowerCase();
    }
}
