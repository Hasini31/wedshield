package com.webshield.ui.controllers;

import com.webshield.dashboard.*;
import javafx.animation.Animation;
import javafx.animation.Interpolator;
import javafx.animation.TranslateTransition;
import javafx.application.Platform;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.chart.*;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.Pane;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.shape.Rectangle;
import javafx.util.Duration;
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

    /* ── Root Containers ───────────────────────────────────────────── */
    @FXML private ScrollPane scrollPaneDashboard;
    @FXML private VBox       dashboardContent;

    /* ── Top Header ─────────────────────────────────────────────────── */
    @FXML private Label  lblLastUpdated;
    @FXML private Button btnRefresh;

    /* ── Row 1: Five Overall Metric Cards ───────────────────────────── */
    @FXML private VBox  cardWebsites;
    @FXML private VBox  cardApiProjects;
    @FXML private VBox  cardWebsiteScans;
    @FXML private VBox  cardApiScans;
    @FXML private VBox  cardTotalScans;

    @FXML private Label lblTitleWebsites;
    @FXML private Label lblTitleApiProjects;
    @FXML private Label lblTitleWebsiteScans;
    @FXML private Label lblTitleApiScans;
    @FXML private Label lblTitleTotalScans;

    @FXML private Label statTotalWebsites;
    @FXML private Label statActiveWebsites;
    @FXML private Label statApiProjects;
    @FXML private Label statApiProjectsSubtitle;
    @FXML private Label statWebsiteScans;
    @FXML private Label statWebsiteScansSubtitle;
    @FXML private Label statApiScans;
    @FXML private Label statApiScansSubtitle;
    @FXML private Label statTotalScans;
    @FXML private Label statScansBreakdown;

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
    @FXML private Label lblApiLastScanChip;

    @FXML private TableView<ApiProjectOverviewRow>          tableApiProjects;
    @FXML private TableColumn<ApiProjectOverviewRow, String> colApiProjName;
    @FXML private TableColumn<ApiProjectOverviewRow, String> colApiProjSpec;
    @FXML private TableColumn<ApiProjectOverviewRow, Number> colApiProjEndpoints;
    @FXML private TableColumn<ApiProjectOverviewRow, Number> colApiProjScans;
    @FXML private TableColumn<ApiProjectOverviewRow, Number> colApiProjTestCases;
    @FXML private TableColumn<ApiProjectOverviewRow, Number> colApiProjExecutions;
    @FXML private TableColumn<ApiProjectOverviewRow, Number> colApiProjFindings;
    @FXML private TableColumn<ApiProjectOverviewRow, Number> colApiProjCritical;
    @FXML private TableColumn<ApiProjectOverviewRow, Number> colApiProjHigh;
    @FXML private TableColumn<ApiProjectOverviewRow, String> colApiProjLastScan;
    @FXML private TableColumn<ApiProjectOverviewRow, String> colApiProjStatus;

    @FXML private Button   btnResetApiSelection;
    @FXML private Label    lblApiChartSubtitle;
    @FXML private PieChart chartApiProjectFindings;
    @FXML private VBox     chartApiEmptyState;
    @FXML private Label    lblApiEmptyTitle;

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

    private final DashboardService service;
    private Map<String, Integer> cachedApiFindingsBySeverity = Map.of();

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
        if (scrollPaneDashboard != null) {
            scrollPaneDashboard.setFitToWidth(true);
            scrollPaneDashboard.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);
        }
        setupMetricCardHoverMarquees();
        configureTables();
        loadDataAsync();
    }

    private void setupMetricCardHoverMarquees() {
        setupHoverMarquee(cardWebsites, lblTitleWebsites);
        setupHoverMarquee(cardApiProjects, lblTitleApiProjects);
        setupHoverMarquee(cardWebsiteScans, lblTitleWebsiteScans);
        setupHoverMarquee(cardApiScans, lblTitleApiScans);
        setupHoverMarquee(cardTotalScans, lblTitleTotalScans);
    }

    private void setupHoverMarquee(VBox card, Label label) {
        if (label == null) return;

        label.setWrapText(false);
        label.setMinWidth(Region.USE_PREF_SIZE);
        label.setPrefWidth(Region.USE_COMPUTED_SIZE);
        label.setMaxWidth(Region.USE_PREF_SIZE);

        Pane container = (label.getParent() instanceof Pane p) ? p : null;
        if (container != null) {
            Rectangle clip = new Rectangle();
            clip.widthProperty().bind(container.widthProperty());
            clip.heightProperty().bind(container.heightProperty());
            container.setClip(clip);
        }

        final Animation[] activeAnimation = new Animation[1];

        EventHandler<MouseEvent> onEnter = e -> {
            if (activeAnimation[0] != null) {
                activeAnimation[0].stop();
            }
            double labelWidth = label.prefWidth(-1);
            double containerWidth = container != null ? container.getWidth() : (card != null ? card.getWidth() : 0);
            double overflow = labelWidth - containerWidth;
            if (overflow > 1.0) {
                double currentX = label.getTranslateX();
                double targetX = -overflow;
                double remainingDist = Math.abs(targetX - currentX);
                double durationMs = Math.max(600, remainingDist * 25);
                TranslateTransition tt = new TranslateTransition(Duration.millis(durationMs), label);
                tt.setToX(targetX);
                tt.setInterpolator(Interpolator.EASE_BOTH);
                activeAnimation[0] = tt;
                tt.play();
            }
        };

        EventHandler<MouseEvent> onExit = e -> {
            if (activeAnimation[0] != null) {
                activeAnimation[0].stop();
            }
            double currentX = label.getTranslateX();
            if (Math.abs(currentX) > 0.5) {
                double durationMs = Math.min(300, Math.max(120, Math.abs(currentX) * 8));
                TranslateTransition tt = new TranslateTransition(Duration.millis(durationMs), label);
                tt.setToX(0);
                tt.setInterpolator(Interpolator.EASE_OUT);
                activeAnimation[0] = tt;
                tt.play();
            } else {
                label.setTranslateX(0);
            }
        };

        if (card != null) {
            card.setOnMouseEntered(onEnter);
            card.setOnMouseExited(onExit);
        }
        if (container != null && container != card) {
            container.setOnMouseEntered(onEnter);
            container.setOnMouseExited(onExit);
        }
        label.setOnMouseEntered(onEnter);
        label.setOnMouseExited(onExit);
    }

    /* ── Table Configuration & Cell Value Factories ────────────────── */

    private void configureTables() {
        tableWebsiteOverview.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        tableApiProjects.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        tableRecentActivity.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);

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

        // 2. API Projects Table
        colApiProjName.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getName()));
        colApiProjSpec.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getSpecDisplay()));
        colApiProjEndpoints.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getEndpointsCount()));
        colApiProjScans.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getScansRun()));
        colApiProjTestCases.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getTestCasesGenerated()));
        colApiProjExecutions.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getRequestsExecuted()));
        colApiProjFindings.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getTotalFindings()));
        colApiProjCritical.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getCriticalFindings()));
        colApiProjHigh.setCellValueFactory(d -> new SimpleIntegerProperty(d.getValue().getHighFindings()));
        colApiProjLastScan.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getLastScanDate()));

        colApiProjStatus.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getStatus()));
        colApiProjStatus.setCellFactory(col -> new TableCell<>() {
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

        // Interactive Selection Listener: dynamically updates the findings pie chart
        tableApiProjects.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, selected) -> {
            if (selected != null) {
                lblApiChartSubtitle.setText("Target: " + selected.getName());
                populateApiProjectPieChart(selected.getFindingsBySeverity(), selected.getName());
            } else {
                lblApiChartSubtitle.setText("Target: All Projects (Overall)");
                populateApiProjectPieChart(cachedApiFindingsBySeverity, "All Projects");
            }
        });

        // Double-click row handler to view API project details
        tableApiProjects.setRowFactory(tv -> {
            TableRow<ApiProjectOverviewRow> row = new TableRow<>();
            row.setOnMouseClicked(event -> {
                if (event.getClickCount() == 2 && !row.isEmpty()) {
                    ApiProjectOverviewRow item = row.getItem();
                    if (item != null && ShellController.getInstance() != null) {
                        ShellController.getInstance().openApiProjectDetails(item.getId());
                    }
                }
            });
            return row;
        });

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
            List<ApiProjectOverviewRow> apiProjects;
            List<SecurityActivityRow> activities;

            @Override
            protected Void call() {
                stats = service.getStatistics();
                websites = service.getWebsiteOverview();
                apiProjects = service.getApiProjectOverview();
                activities = service.getRecentSecurityActivity();
                return null;
            }

            @Override
            protected void succeeded() {
                Platform.runLater(() -> {
                    populateUI(stats, websites, apiProjects, activities);
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
                            List<ApiProjectOverviewRow> apiProjects,
                            List<SecurityActivityRow> activities) {
        // Section A: Overall Metric Cards (5 Cards)
        statTotalWebsites.setText(String.valueOf(stats.getTotalWebsites()));
        statActiveWebsites.setText(stats.getActiveWebsites() + " active");
        statApiProjects.setText(String.valueOf(stats.getTotalApiProjects()));
        if (statApiProjectsSubtitle != null) {
            statApiProjectsSubtitle.setText("OpenAPI specs");
        }
        statWebsiteScans.setText(String.valueOf(stats.getTotalWebsiteScans()));
        statWebsiteScansSubtitle.setText(stats.getWebsitesScanned() + " targets scanned");
        statApiScans.setText(String.valueOf(stats.getTotalApiScans()));
        statApiScansSubtitle.setText(stats.getApiTestCasesExecuted() + " requests executed");
        statTotalScans.setText(String.valueOf(stats.getTotalWebsiteScans() + stats.getTotalApiScans()));
        statScansBreakdown.setText(stats.getTotalWebsiteScans() + " Web · " + stats.getTotalApiScans() + " API");

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
        if (lblApiLastScanChip != null) {
            lblApiLastScanChip.setText(stats.getLastApiScanDate());
        }

        cachedApiFindingsBySeverity = stats.getApiFindingsBySeverity();
        tableApiProjects.setItems(FXCollections.observableArrayList(apiProjects));

        // Interactive findings pie chart synchronization
        ApiProjectOverviewRow selected = tableApiProjects.getSelectionModel().getSelectedItem();
        if (selected != null) {
            populateApiProjectPieChart(selected.getFindingsBySeverity(), selected.getName());
        } else {
            populateApiProjectPieChart(cachedApiFindingsBySeverity, "All Projects (Overall)");
        }

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
    }

    /* ── Chart Population ──────────────────────────────────────────── */

    @FXML
    private void onResetApiProjectSelection() {
        if (tableApiProjects != null) {
            tableApiProjects.getSelectionModel().clearSelection();
        }
    }

    private void populateApiProjectPieChart(Map<String, Integer> severityMap, String targetName) {
        if (chartApiProjectFindings == null) return;
        chartApiProjectFindings.getData().clear();

        if (lblApiChartSubtitle != null) {
            lblApiChartSubtitle.setText("Target: " + (targetName != null ? targetName : "All Projects"));
        }

        int total = severityMap != null ? severityMap.values().stream().mapToInt(Integer::intValue).sum() : 0;
        boolean hasData = total > 0;

        if (chartApiEmptyState != null) {
            chartApiEmptyState.setVisible(!hasData);
            chartApiEmptyState.setManaged(!hasData);
        }
        chartApiProjectFindings.setVisible(hasData);
        chartApiProjectFindings.setManaged(hasData);

        if (!hasData || severityMap == null) return;

        ObservableList<PieChart.Data> pieData = FXCollections.observableArrayList();
        for (String sev : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")) {
            int val = severityMap.getOrDefault(sev, 0);
            if (val > 0) {
                double pct = (val * 100.0) / total;
                String displaySev = switch (sev) {
                    case "INFORMATIONAL" -> "Info";
                    case "CRITICAL" -> "Critical";
                    case "HIGH" -> "High";
                    case "MEDIUM" -> "Medium";
                    case "LOW" -> "Low";
                    default -> sev;
                };
                pieData.add(new PieChart.Data(String.format("%s: %d (%.1f%%)", displaySev, val, pct), val));
            }
        }
        chartApiProjectFindings.setData(pieData);

        // Apply distinct cybersecurity colors to slices
        for (PieChart.Data d : pieData) {
            if (d.getNode() != null) {
                String name = d.getName().toUpperCase();
                String col = "#64748B"; // default slate info
                if (name.contains("CRITICAL")) col = "#DC2626";
                else if (name.contains("HIGH")) col = "#EA580C";
                else if (name.contains("MEDIUM")) col = "#D97706";
                else if (name.contains("LOW")) col = "#2563EB";
                d.getNode().setStyle("-fx-pie-color: " + col + ";");
                Tooltip.install(d.getNode(), new Tooltip(d.getName()));
            }
        }
    }

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
