package com.webshield.ui.controllers;

import com.webshield.dashboard.*;
import javafx.application.Platform;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.chart.*;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * Controller for the WebShield Unified Security Command Center Dashboard.
 *
 * <p>Provides comprehensive real-time telemetry, vulnerability distribution,
 * website reconnaissance posture, API mutation testing statistics, recent unified
 * assessment activity, and prioritized critical findings.
 *
 * <p>Data retrieval runs asynchronously on background daemon threads so the JavaFX UI
 * thread never freezes.
 */
@Component
@Scope("prototype")
public class DashboardController {

    private static final Logger log = LoggerFactory.getLogger(DashboardController.class);
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm:ss");

    /* ── Top Header ─────────────────────────────────────────────────── */
    @FXML private Label  lblLastUpdated;
    @FXML private Button btnRefresh;

    /* ── Row 1: Six Overall Metric Cards ────────────────────────────── */
    @FXML private Label statTotalWebsites;
    @FXML private Label statActiveWebsites;
    @FXML private Label statApiProjects;
    @FXML private Label statTotalScans;
    @FXML private Label statScansBreakdown;
    @FXML private Label statApiExecuted;
    @FXML private Label statApiGenerated;
    @FXML private Label statTotalFindings;
    @FXML private Label statFindingsBreakdown;
    @FXML private Label statCriticalFindings;
    @FXML private Label statCriticalBreakdown;

    /* ── Row 2: Website Security Overview ───────────────────────────── */
    @FXML private Label lblWebRegistered;
    @FXML private Label lblWebScanned;
    @FXML private Label lblWebPagesDiscovered;
    @FXML private Label lblWebPagesTested;
    @FXML private Label lblWebFindings;
    @FXML private Label lblWebLastScan;

    @FXML private TableView<WebsiteOverviewRow>          tableWebsiteOverview;
    @FXML private TableColumn<WebsiteOverviewRow, String> colWebName;
    @FXML private TableColumn<WebsiteOverviewRow, String> colWebUrl;
    @FXML private TableColumn<WebsiteOverviewRow, Number> colWebDiscovered;
    @FXML private TableColumn<WebsiteOverviewRow, Number> colWebTested;
    @FXML private TableColumn<WebsiteOverviewRow, Number> colWebFindings;
    @FXML private TableColumn<WebsiteOverviewRow, Number> colWebCritical;
    @FXML private TableColumn<WebsiteOverviewRow, Number> colWebHigh;
    @FXML private TableColumn<WebsiteOverviewRow, String> colWebLastScan;
    @FXML private TableColumn<WebsiteOverviewRow, String> colWebStatus;
    @FXML private TableColumn<WebsiteOverviewRow, Void>   colWebAction;

    /* ── Row 3: API Security Overview ───────────────────────────────── */
    @FXML private Label lblApiProjectsChip;
    @FXML private Label lblApiEndpoints;
    @FXML private Label lblApiScansChip;
    @FXML private Label lblApiTestCasesGenChip;
    @FXML private Label lblApiTestCasesExecChip;
    @FXML private Label lblApiFindingsChip;

    @FXML private TableView<ApiCategoryStat>          tableApiCategories;
    @FXML private TableColumn<ApiCategoryStat, String> colCatName;
    @FXML private TableColumn<ApiCategoryStat, Number> colCatGenerated;
    @FXML private TableColumn<ApiCategoryStat, Number> colCatExecuted;
    @FXML private TableColumn<ApiCategoryStat, Number> colCatFindings;

    @FXML private BarChart<String, Number> chartApiCategories;
    @FXML private CategoryAxis             axisApiCatX;
    @FXML private NumberAxis               axisApiCatY;

    /* ── Row 4: Vulnerability Severity Distribution ─────────────────── */
    @FXML private PieChart chartSeverityDistribution;
    @FXML private VBox     chartEmptyState;

    @FXML private Label lblWebCrit;
    @FXML private Label lblWebHigh;
    @FXML private Label lblWebMed;
    @FXML private Label lblWebLow;
    @FXML private Label lblWebInfo;

    @FXML private Label lblApiCrit;
    @FXML private Label lblApiHigh;
    @FXML private Label lblApiMed;
    @FXML private Label lblApiLow;
    @FXML private Label lblApiInfo;

    /* ── Row 5: Recent Security Activity ────────────────────────────── */
    @FXML private TableView<SecurityActivityRow>          tableRecentActivity;
    @FXML private TableColumn<SecurityActivityRow, String> colActScanId;
    @FXML private TableColumn<SecurityActivityRow, String> colActTargetName;
    @FXML private TableColumn<SecurityActivityRow, String> colActTargetType;
    @FXML private TableColumn<SecurityActivityRow, String> colActScanDate;
    @FXML private TableColumn<SecurityActivityRow, String> colActDuration;
    @FXML private TableColumn<SecurityActivityRow, String> colActUnitsTested;
    @FXML private TableColumn<SecurityActivityRow, Number> colActFindings;
    @FXML private TableColumn<SecurityActivityRow, String> colActStatus;
    @FXML private TableColumn<SecurityActivityRow, Void>   colActAction;

    /* ── Row 6: Critical Security Findings ──────────────────────────── */
    @FXML private TableView<CriticalFindingRow>          tableCriticalFindings;
    @FXML private TableColumn<CriticalFindingRow, String> colCritName;
    @FXML private TableColumn<CriticalFindingRow, String> colCritTarget;
    @FXML private TableColumn<CriticalFindingRow, String> colCritType;
    @FXML private TableColumn<CriticalFindingRow, String> colCritCategory;
    @FXML private TableColumn<CriticalFindingRow, String> colCritSeverity;
    @FXML private TableColumn<CriticalFindingRow, String> colCritConfidence;
    @FXML private TableColumn<CriticalFindingRow, String> colCritStatus;
    @FXML private TableColumn<CriticalFindingRow, Void>   colCritAction;

    private final DashboardService service;

    public DashboardController() {
        this(com.webshield.config.SpringContext.getBean(DashboardService.class));
    }

    public DashboardController(DashboardService service) {
        this.service = service != null ? service : new DashboardService();
    }

    /* ── Lifecycle ─────────────────────────────────────────────────── */

    @FXML
    public void initialize() {
        log.info("Initializing Unified Security Command Center Dashboard");
        configureTables();
        loadDataAsync();
    }

    /* ── Table Configuration & Cell Value Factories ────────────────── */

    private void configureTables() {
        // 1. Website Overview Table
        colWebName.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getName()));
        colWebUrl.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getUrl()));
        colWebDiscovered.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getPagesDiscovered()));
        colWebTested.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getPagesTested()));
        colWebFindings.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getTotalFindings()));
        colWebCritical.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getCriticalFindings()));
        colWebHigh.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getHighFindings()));
        colWebLastScan.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getLastScan()));

        // Styled Status Column
        colWebStatus.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getScanStatus()));
        colWebStatus.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    setGraphic(null);
                } else {
                    Label badge = new Label(item);
                    badge.setStyle(getStatusBadgeStyle(item));
                    setGraphic(badge);
                    setText(null);
                }
            }
        });

        // Action Button Column
        colWebAction.setCellFactory(col -> new TableCell<>() {
            private final Button btn = new Button("View Results");
            {
                btn.getStyleClass().add("ws-btn-secondary");
                btn.setStyle("-fx-font-size: 11px; -fx-padding: 3 8;");
                btn.setOnAction(e -> {
                    WebsiteOverviewRow row = getTableView().getItems().get(getIndex());
                    if (row != null && ShellController.getInstance() != null) {
                        if (row.getLastScanId() != null) {
                            ShellController.getInstance().openReportsForScan(row.getLastScanId());
                        } else {
                            ShellController.getInstance().openWebsiteDetails(row.getId());
                        }
                    }
                });
            }
            @Override
            protected void updateItem(Void item, boolean empty) {
                super.updateItem(item, empty);
                setGraphic(empty ? null : btn);
            }
        });

        // 2. API Categories Table
        colCatName.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().category()));
        colCatGenerated.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().generatedCount()));
        colCatExecuted.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().executedCount()));
        colCatFindings.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().findingsCount()));

        // 3. Recent Security Activity Table
        colActScanId.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getDisplayId()));
        colActTargetName.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getTargetName()));
        colActTargetType.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getTargetType()));
        colActTargetType.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setGraphic(null);
                    setText(null);
                } else {
                    Label badge = new Label(item);
                    boolean isApi = "API".equalsIgnoreCase(item);
                    String bg = isApi ? "#F5F3FF" : "#EFF6FF";
                    String textCol = isApi ? "#7C3AED" : "#2563EB";
                    badge.setStyle("-fx-background-color: " + bg + "; -fx-text-fill: " + textCol + "; -fx-font-size: 10px; -fx-font-weight: bold; -fx-padding: 2 6; -fx-background-radius: 4;");
                    setGraphic(badge);
                    setText(null);
                }
            }
        });
        colActScanDate.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getScanDate()));
        colActDuration.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getDuration()));
        colActUnitsTested.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getUnitsTested()));
        colActFindings.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getFindingsCount()));
        colActStatus.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getScanStatus()));
        colActStatus.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setGraphic(null);
                    setText(null);
                } else {
                    Label badge = new Label(item);
                    badge.setStyle(getStatusBadgeStyle(item));
                    setGraphic(badge);
                    setText(null);
                }
            }
        });
        colActAction.setCellFactory(col -> new TableCell<>() {
            private final Button btn = new Button("View Results");
            {
                btn.getStyleClass().add("ws-btn-secondary");
                btn.setStyle("-fx-font-size: 11px; -fx-padding: 3 8;");
                btn.setOnAction(e -> {
                    SecurityActivityRow row = getTableView().getItems().get(getIndex());
                    if (row != null && ShellController.getInstance() != null) {
                        if ("WEBSITE".equalsIgnoreCase(row.getTargetType())) {
                            ShellController.getInstance().openReportsForScan(row.getRawScanId());
                        } else {
                            ShellController.getInstance().openApiFindingsForScan(row.getRawScanId());
                        }
                    }
                });
            }
            @Override
            protected void updateItem(Void item, boolean empty) {
                super.updateItem(item, empty);
                setGraphic(empty ? null : btn);
            }
        });

        // 4. Critical Findings Table
        colCritName.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getFindingName()));
        colCritTarget.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getTarget()));
        colCritType.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getTargetType()));
        colCritType.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setGraphic(null);
                    setText(null);
                } else {
                    Label badge = new Label(item);
                    boolean isApi = "API".equalsIgnoreCase(item);
                    String bg = isApi ? "#F5F3FF" : "#EFF6FF";
                    String textCol = isApi ? "#7C3AED" : "#2563EB";
                    badge.setStyle("-fx-background-color: " + bg + "; -fx-text-fill: " + textCol + "; -fx-font-size: 10px; -fx-font-weight: bold; -fx-padding: 2 6; -fx-background-radius: 4;");
                    setGraphic(badge);
                    setText(null);
                }
            }
        });
        colCritCategory.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getCategory()));
        colCritSeverity.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getSeverity()));
        colCritSeverity.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setGraphic(null);
                    setText(null);
                } else {
                    Label badge = new Label(item);
                    boolean isCrit = "CRITICAL".equalsIgnoreCase(item);
                    String bg = isCrit ? "#FEF2F2" : "#FFF7ED";
                    String textCol = isCrit ? "#DC2626" : "#EA580C";
                    badge.setStyle("-fx-background-color: " + bg + "; -fx-text-fill: " + textCol + "; -fx-font-size: 10px; -fx-font-weight: bold; -fx-padding: 2 6; -fx-background-radius: 4;");
                    setGraphic(badge);
                    setText(null);
                }
            }
        });
        colCritConfidence.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getConfidence()));
        colCritStatus.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getReviewStatus()));
        colCritAction.setCellFactory(col -> new TableCell<>() {
            private final Button btn = new Button("View Details");
            {
                btn.getStyleClass().add("ws-btn-secondary");
                btn.setStyle("-fx-font-size: 11px; -fx-padding: 3 8;");
                btn.setOnAction(e -> {
                    CriticalFindingRow row = getTableView().getItems().get(getIndex());
                    if (row != null && ShellController.getInstance() != null) {
                        if ("WEBSITE".equalsIgnoreCase(row.getTargetType())) {
                            ShellController.getInstance().openReportsForScan(row.getScanId());
                        } else {
                            ShellController.getInstance().openApiFindingsForScan(row.getScanId());
                        }
                    }
                });
            }
            @Override
            protected void updateItem(Void item, boolean empty) {
                super.updateItem(item, empty);
                setGraphic(empty ? null : btn);
            }
        });
    }

    private String getStatusBadgeStyle(String status) {
        if (status == null) return "-fx-text-fill: #64748B;";
        String s = status.toUpperCase();
        if (s.contains("COMPLETED") || s.contains("ACTIVE")) {
            return "-fx-background-color: #ECFDF5; -fx-text-fill: #059669; -fx-font-size: 10px; -fx-font-weight: bold; -fx-padding: 2 6; -fx-background-radius: 4;";
        } else if (s.contains("QUEUED") || s.contains("PENDING") || s.contains("SCANNING") || s.contains("CRAWLING")) {
            return "-fx-background-color: #FFFBEB; -fx-text-fill: #D97706; -fx-font-size: 10px; -fx-font-weight: bold; -fx-padding: 2 6; -fx-background-radius: 4;";
        } else if (s.contains("FAIL") || s.contains("CANCEL")) {
            return "-fx-background-color: #FEF2F2; -fx-text-fill: #DC2626; -fx-font-size: 10px; -fx-font-weight: bold; -fx-padding: 2 6; -fx-background-radius: 4;";
        }
        return "-fx-background-color: #F8FAFC; -fx-text-fill: #64748B; -fx-font-size: 10px; -fx-font-weight: bold; -fx-padding: 2 6; -fx-background-radius: 4;";
    }

    /* ── Asynchronous Data Loading ─────────────────────────────────── */

    @FXML
    public void onRefresh() {
        loadDataAsync();
    }

    private void loadDataAsync() {
        if (lblLastUpdated != null) {
            lblLastUpdated.setText("Refreshing telemetry...");
        }

        Task<Void> task = new Task<>() {
            DashboardStatistics stats;
            List<WebsiteOverviewRow> websites;
            List<SecurityActivityRow> activities;
            List<CriticalFindingRow> criticals;

            @Override
            protected Void call() {
                stats = service.getStatistics();
                websites = service.getWebsiteOverview();
                activities = service.getRecentSecurityActivity();
                criticals = service.getCriticalFindings();
                return null;
            }

            @Override
            protected void succeeded() {
                Platform.runLater(() -> {
                    populateUI(stats, websites, activities, criticals);
                    if (lblLastUpdated != null) {
                        lblLastUpdated.setText("Last refreshed: " + LocalDateTime.now().format(TIME_FMT));
                    }
                });
            }

            @Override
            protected void failed() {
                log.error("Dashboard background data load failed", getException());
                Platform.runLater(() -> {
                    populateUI(DashboardStatistics.empty(), List.of(), List.of(), List.of());
                    if (lblLastUpdated != null) {
                        lblLastUpdated.setText("Refresh failed. Displaying offline data.");
                    }
                });
            }
        };

        Thread t = new Thread(task, "dashboard-telemetry-loader");
        t.setDaemon(true);
        t.start();
    }

    /* ── UI Population ─────────────────────────────────────────────── */

    private void populateUI(DashboardStatistics stats,
                            List<WebsiteOverviewRow> websites,
                            List<SecurityActivityRow> activities,
                            List<CriticalFindingRow> criticals) {
        // Section A: Overall Metric Cards
        statTotalWebsites.setText(String.valueOf(stats.getTotalWebsites()));
        statActiveWebsites.setText(stats.getActiveWebsites() + " active");
        statApiProjects.setText(String.valueOf(stats.getTotalApiProjects()));
        statTotalScans.setText(String.valueOf(stats.getTotalScans()));
        statScansBreakdown.setText(stats.getTotalWebsiteScans() + " Web · " + stats.getTotalApiScans() + " API");
        statApiExecuted.setText(String.valueOf(stats.getApiTestCasesExecuted()));
        statApiGenerated.setText(stats.getApiTestCasesExecuted() + " executed · " + stats.getApiTestCasesGenerated() + " gen");
        statTotalFindings.setText(String.valueOf(stats.getTotalFindings()));
        statFindingsBreakdown.setText(stats.getTotalWebsiteFindings() + " Web · " + stats.getTotalApiFindings() + " API");
        statCriticalFindings.setText(String.valueOf(stats.getCriticalFindings()));
        statCriticalBreakdown.setText(stats.getCriticalWebsiteFindings() + " Web · " + stats.getCriticalApiFindings() + " API");

        // Section B: Website Security Overview
        lblWebRegistered.setText(String.valueOf(stats.getTotalWebsites()));
        lblWebScanned.setText(String.valueOf(stats.getWebsitesScanned()));
        lblWebPagesDiscovered.setText(String.valueOf(stats.getTotalPagesDiscovered()));
        lblWebPagesTested.setText(String.valueOf(stats.getTotalPagesTested()));
        lblWebFindings.setText(String.valueOf(stats.getTotalWebsiteFindings()));
        lblWebLastScan.setText(stats.getLastWebsiteScanDate());
        tableWebsiteOverview.setItems(FXCollections.observableArrayList(websites));

        // Section C: API Security Overview
        lblApiProjectsChip.setText(String.valueOf(stats.getTotalApiProjects()));
        lblApiEndpoints.setText(String.valueOf(stats.getTotalApiEndpoints()));
        lblApiScansChip.setText(String.valueOf(stats.getTotalApiScans()));
        lblApiTestCasesGenChip.setText(String.valueOf(stats.getApiTestCasesGenerated()));
        lblApiTestCasesExecChip.setText(String.valueOf(stats.getApiTestCasesExecuted()));
        lblApiFindingsChip.setText(String.valueOf(stats.getTotalApiFindings()));

        List<ApiCategoryStat> catStats = stats.getApiCategoryStats();
        tableApiCategories.setItems(FXCollections.observableArrayList(catStats));
        populateApiCategoryChart(catStats);

        // Section D: Severity Distribution & Engine Breakdown
        populateSeverityPieChart(stats.getFindingsBySeverity());

        Map<String, Integer> webSev = stats.getWebsiteFindingsBySeverity();
        lblWebCrit.setText(String.valueOf(webSev.getOrDefault("CRITICAL", 0)));
        lblWebHigh.setText(String.valueOf(webSev.getOrDefault("HIGH", 0)));
        lblWebMed.setText(String.valueOf(webSev.getOrDefault("MEDIUM", 0)));
        lblWebLow.setText(String.valueOf(webSev.getOrDefault("LOW", 0)));
        lblWebInfo.setText(String.valueOf(webSev.getOrDefault("INFORMATIONAL", 0)));

        Map<String, Integer> apiSev = stats.getApiFindingsBySeverity();
        lblApiCrit.setText(String.valueOf(apiSev.getOrDefault("CRITICAL", 0)));
        lblApiHigh.setText(String.valueOf(apiSev.getOrDefault("HIGH", 0)));
        lblApiMed.setText(String.valueOf(apiSev.getOrDefault("MEDIUM", 0)));
        lblApiLow.setText(String.valueOf(apiSev.getOrDefault("LOW", 0)));
        lblApiInfo.setText(String.valueOf(apiSev.getOrDefault("INFORMATIONAL", 0)));

        // Section E: Recent Security Activity Table
        tableRecentActivity.setItems(FXCollections.observableArrayList(activities));

        // Section F: Critical Security Findings Table
        tableCriticalFindings.setItems(FXCollections.observableArrayList(criticals));
    }

    /* ── Chart Population ──────────────────────────────────────────── */

    private void populateSeverityPieChart(Map<String, Integer> severityMap) {
        chartSeverityDistribution.getData().clear();
        boolean hasData = severityMap != null && severityMap.values().stream().anyMatch(v -> v > 0);

        if (chartEmptyState != null) {
            chartEmptyState.setVisible(!hasData);
            chartEmptyState.setManaged(!hasData);
        }
        chartSeverityDistribution.setVisible(hasData);
        chartSeverityDistribution.setManaged(hasData);

        if (!hasData || severityMap == null) return;

        ObservableList<PieChart.Data> pieData = FXCollections.observableArrayList();
        for (String sev : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")) {
            int val = severityMap.getOrDefault(sev, 0);
            if (val > 0) {
                pieData.add(new PieChart.Data(sev + " (" + val + ")", val));
            }
        }
        chartSeverityDistribution.setData(pieData);

        // Apply distinct cybersecurity colors to slices
        for (PieChart.Data d : pieData) {
            if (d.getNode() != null) {
                String name = d.getName().toUpperCase();
                String col = "#64748B";
                if (name.contains("CRITICAL")) col = "#DC2626";
                else if (name.contains("HIGH")) col = "#EA580C";
                else if (name.contains("MEDIUM")) col = "#D97706";
                else if (name.contains("LOW")) col = "#2563EB";
                d.getNode().setStyle("-fx-pie-color: " + col + ";");
            }
        }
    }

    private void populateApiCategoryChart(List<ApiCategoryStat> catStats) {
        if (chartApiCategories == null) return;
        chartApiCategories.getData().clear();

        XYChart.Series<String, Number> genSeries = new XYChart.Series<>();
        genSeries.setName("Generated");

        for (ApiCategoryStat st : catStats) {
            genSeries.getData().add(new XYChart.Data<>(formatCategoryLabel(st.category()), st.generatedCount()));
        }
        chartApiCategories.getData().add(genSeries);
    }

    private String formatCategoryLabel(String cat) {
        if (cat == null) return "";
        return switch (cat.toUpperCase()) {
            case "VALID_SMOKE" -> "Smoke";
            case "BOUNDARY" -> "Boundary";
            case "MISSING_REQUIRED" -> "Missing";
            case "TYPE_CONFUSION" -> "Type";
            case "SECURITY_PROBES" -> "Probes";
            default -> cat;
        };
    }

    /* ── Quick Actions Navigation ──────────────────────────────────── */

    @FXML
    private void onViewAllWebsites() {
        if (ShellController.getInstance() != null) {
            ShellController.getInstance().openWebsites();
        }
    }

    @FXML
    private void onViewAllApiProjects() {
        if (ShellController.getInstance() != null) {
            ShellController.getInstance().openApiProjects();
        }
    }

    @FXML
    private void onActionRegisterWebsite() {
        if (ShellController.getInstance() != null) {
            ShellController.getInstance().openWebsites();
        }
    }

    @FXML
    private void onActionAddApiProject() {
        if (ShellController.getInstance() != null) {
            ShellController.getInstance().openApiProjects();
        }
    }

    @FXML
    private void onActionStartWebsiteScan() {
        if (ShellController.getInstance() != null) {
            ShellController.getInstance().openSecurityScansFor(null);
        }
    }

    @FXML
    private void onActionStartApiScan() {
        if (ShellController.getInstance() != null) {
            ShellController.getInstance().openApiScanFor(null);
        }
    }
}
