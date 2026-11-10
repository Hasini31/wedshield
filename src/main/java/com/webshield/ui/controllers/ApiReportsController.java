package com.webshield.ui.controllers;

import com.webshield.api.dto.ApiScanDto;
import com.webshield.api.llm.LlmService;
import com.webshield.api.reporting.*;
import com.webshield.api.service.ApiPersistenceService;
import com.webshield.auth.SessionManager;
import com.webshield.config.SpringContext;
import com.webshield.models.User;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.util.StringConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import java.awt.Desktop;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * JavaFX Controller for API security report generation, format selection,
 * AI assistance consent, and historical report archiving.
 */
@Component
@Scope("prototype")
public class ApiReportsController {

    private static final Logger log = LoggerFactory.getLogger(ApiReportsController.class);
    private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm");

    @FXML private Button btnRefresh;

    // Form Controls
    @FXML private ComboBox<ApiScanDto> cbScans;
    @FXML private RadioButton rbPdf;
    @FXML private RadioButton rbHtml;
    private ToggleGroup formatGroup;

    @FXML private CheckBox chkExecutiveSummary;
    @FXML private CheckBox chkScope;
    @FXML private CheckBox chkMethodology;
    @FXML private CheckBox chkVulnerabilityOverview;
    @FXML private CheckBox chkDetailedFindings;
    @FXML private CheckBox chkStatistics;
    @FXML private CheckBox chkRemediation;
    @FXML private CheckBox chkLimitations;

    @FXML private Label lblProviderBadge;
    @FXML private CheckBox chkIncludeAi;
    @FXML private CheckBox chkExternalConsent;

    @FXML private Button btnGenerateReport;
    @FXML private ProgressBar pbGenerating;
    @FXML private Label lblGenerationStatus;

    // Latest Report Card
    @FXML private VBox paneLatestReport;
    @FXML private Label lblLatestFilename;
    @FXML private Button btnOpenReport;
    @FXML private Button btnOpenFolder;

    // Table Archive
    @FXML private Label lblReportCount;
    @FXML private TableView<ApiReportMetadata> tableReports;
    @FXML private TableColumn<ApiReportMetadata, String> colReportId;
    @FXML private TableColumn<ApiReportMetadata, String> colFormat;
    @FXML private TableColumn<ApiReportMetadata, String> colScanName;
    @FXML private TableColumn<ApiReportMetadata, String> colSize;
    @FXML private TableColumn<ApiReportMetadata, String> colHasAi;
    @FXML private TableColumn<ApiReportMetadata, String> colGeneratedAt;

    @FXML private Button btnOpenSelected;
    @FXML private Button btnDeleteReport;

    private final ApiReportService reportService;
    private final ApiPersistenceService persistenceService;
    private final LlmService llmService;

    private final ObservableList<ApiReportMetadata> reportsMaster = FXCollections.observableArrayList();
    private Path latestReportPath = null;
    private Long preselectedScanId = null;

    public ApiReportsController() {
        this(SpringContext.getBean(ApiReportService.class),
                SpringContext.getBean(ApiPersistenceService.class),
                SpringContext.getBean(LlmService.class));
    }

    public ApiReportsController(ApiReportService reportService,
                                ApiPersistenceService persistenceService,
                                LlmService llmService) {
        this.reportService = reportService;
        this.persistenceService = persistenceService;
        this.llmService = llmService;
    }

    @FXML
    public void initialize() {
        configureFormatToggle();
        configureTable();
        configureAiBindings();
        loadScansAsync();
        loadReportsAsync();
    }

    private void configureFormatToggle() {
        formatGroup = new ToggleGroup();
        if (rbPdf != null) rbPdf.setToggleGroup(formatGroup);
        if (rbHtml != null) rbHtml.setToggleGroup(formatGroup);
    }

    private void configureAiBindings() {
        if (chkIncludeAi != null && chkExternalConsent != null) {
            chkExternalConsent.disableProperty().bind(chkIncludeAi.selectedProperty().not());
            chkIncludeAi.selectedProperty().addListener((obs, oldV, selected) -> {
                if (!selected) {
                    chkExternalConsent.setSelected(false);
                }
            });
        }
        if (lblProviderBadge != null && llmService != null) {
            String pName = llmService.getConfiguration().providerName();
            lblProviderBadge.setText("Provider: " + (pName != null ? pName.toUpperCase() : "MOCK"));
        }
    }

    private void configureTable() {
        if (colReportId != null) colReportId.setCellValueFactory(d -> new SimpleStringProperty("#" + d.getValue().id()));
        if (colFormat != null) colFormat.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().reportFormat()));
        if (colScanName != null) colScanName.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().reportName()));
        if (colSize != null) colSize.setCellValueFactory(d -> {
            long bytes = d.getValue().fileSizeBytes();
            return new SimpleStringProperty(bytes > 1024 ? (bytes / 1024) + " KB" : bytes + " B");
        });
        if (colHasAi != null) colHasAi.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().hasAiExplanations() ? "Yes (AI)" : "Deterministic"));
        if (colGeneratedAt != null) colGeneratedAt.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().createdAt() != null ? d.getValue().createdAt().format(DATE_FMT) : "—"));

        if (tableReports != null) {
            tableReports.setItems(reportsMaster);
            var selectedProp = tableReports.getSelectionModel().selectedItemProperty();
            if (btnOpenSelected != null) btnOpenSelected.disableProperty().bind(selectedProp.isNull());
            if (btnDeleteReport != null) btnDeleteReport.disableProperty().bind(selectedProp.isNull());
        }

        if (cbScans != null) {
            cbScans.setConverter(new StringConverter<>() {
                @Override
                public String toString(ApiScanDto s) {
                    return s != null ? s.scanName() + " (#" + s.id() + " - " + s.status() + ")" : "Select a scan";
                }

                @Override
                public ApiScanDto fromString(String string) {
                    return null;
                }
            });
        }
    }

    public void setPreselectedScanId(Long scanId) {
        this.preselectedScanId = scanId;
        if (cbScans != null && cbScans.getItems() != null) {
            cbScans.getItems().stream()
                    .filter(s -> s.id().equals(scanId))
                    .findFirst()
                    .ifPresent(cbScans::setValue);
        }
    }

    public void loadScansAsync() {
        User user = SessionManager.getInstance().getCurrentUser();
        Long userId = user != null ? user.getId() : 1L;

        Task<List<ApiScanDto>> task = new Task<>() {
            @Override
            protected List<ApiScanDto> call() {
                return persistenceService != null ? persistenceService.getScansForUser(userId) : List.of();
            }

            @Override
            protected void succeeded() {
                List<ApiScanDto> scans = getValue();
                if (cbScans != null) {
                    cbScans.setItems(FXCollections.observableArrayList(scans));
                    if (preselectedScanId != null) {
                        setPreselectedScanId(preselectedScanId);
                    } else if (!scans.isEmpty()) {
                        cbScans.getSelectionModel().select(0);
                    }
                }
            }
        };
        Thread thread = new Thread(task, "load-reports-scans");
        thread.setDaemon(true);
        thread.start();
    }

    public void loadReportsAsync() {
        User user = SessionManager.getInstance().getCurrentUser();
        Long userId = user != null ? user.getId() : 1L;

        Task<List<ApiReportMetadata>> task = new Task<>() {
            @Override
            protected List<ApiReportMetadata> call() {
                return reportService != null ? reportService.getReportsForUser(userId) : List.of();
            }

            @Override
            protected void succeeded() {
                reportsMaster.setAll(getValue());
                if (lblReportCount != null) {
                    lblReportCount.setText(reportsMaster.size() + " reports");
                }
            }
        };
        Thread thread = new Thread(task, "load-reports-archive");
        thread.setDaemon(true);
        thread.start();
    }

    @FXML
    public void onGenerateReport() {
        ApiScanDto scan = cbScans != null ? cbScans.getValue() : null;
        if (scan == null) {
            updateStatus("Please select a valid scan before generating a report.", true);
            return;
        }

        User user = SessionManager.getInstance().getCurrentUser();
        Long userId = user != null ? user.getId() : 1L;

        String format = (rbHtml != null && rbHtml.isSelected()) ? ApiReportConfiguration.FORMAT_HTML : ApiReportConfiguration.FORMAT_PDF;
        boolean withAi = chkIncludeAi != null && chkIncludeAi.isSelected();
        boolean consent = chkExternalConsent != null && chkExternalConsent.isSelected();

        ApiReportConfiguration config = new ApiReportConfiguration(
                "WebShield API Security Assessment Report",
                format,
                chkExecutiveSummary == null || chkExecutiveSummary.isSelected(),
                chkScope == null || chkScope.isSelected(),
                chkMethodology == null || chkMethodology.isSelected(),
                chkVulnerabilityOverview == null || chkVulnerabilityOverview.isSelected(),
                chkDetailedFindings == null || chkDetailedFindings.isSelected(),
                chkStatistics == null || chkStatistics.isSelected(),
                chkRemediation == null || chkRemediation.isSelected(),
                chkLimitations == null || chkLimitations.isSelected(),
                withAi,
                consent,
                ApiReportConfiguration.DEFAULT_OUTPUT_DIR
        );

        setGeneratingState(true);
        updateStatus("Generating " + format + " report...", false);

        Task<ApiReportExportResult> task = new Task<>() {
            @Override
            protected ApiReportExportResult call() {
                return reportService.generateReport(scan.id(), userId, config);
            }

            @Override
            protected void succeeded() {
                setGeneratingState(false);
                ApiReportExportResult res = getValue();
                if (res != null && res.success()) {
                    latestReportPath = res.filePath();
                    updateStatus("✓ Report generated successfully: " + res.filePath().getFileName(), false);
                    if (paneLatestReport != null) paneLatestReport.setVisible(true);
                    if (lblLatestFilename != null) lblLatestFilename.setText(res.filePath().getFileName().toString());
                    loadReportsAsync();
                } else {
                    updateStatus("Failed to generate report: " + (res != null ? res.message() : "Unknown error"), true);
                }
            }

            @Override
            protected void failed() {
                setGeneratingState(false);
                Throwable e = getException();
                log.error("Report generation failed", e);
                updateStatus("Error generating report: " + (e != null ? e.getMessage() : "Unknown"), true);
            }
        };

        Thread thread = new Thread(task, "report-generator-worker");
        thread.setDaemon(true);
        thread.start();
    }

    @FXML
    public void onOpenLatestReport() {
        if (latestReportPath != null) {
            openFile(latestReportPath);
        }
    }

    @FXML
    public void onOpenReportFolder() {
        if (latestReportPath != null && latestReportPath.getParent() != null) {
            openFolder(latestReportPath.getParent());
        }
    }

    @FXML
    public void onOpenSelectedReport() {
        ApiReportMetadata selected = tableReports != null ? tableReports.getSelectionModel().getSelectedItem() : null;
        if (selected != null && selected.filePath() != null) {
            openFile(Paths.get(selected.filePath()));
        }
    }

    @FXML
    public void onDeleteSelectedReport() {
        ApiReportMetadata selected = tableReports != null ? tableReports.getSelectionModel().getSelectedItem() : null;
        if (selected == null || reportService == null) return;

        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle("Confirm Deletion");
        alert.setHeaderText("Delete Report #" + selected.id());
        alert.setContentText("Are you sure you want to delete report '" + selected.reportName() + "'?");

        alert.showAndWait().ifPresent(btn -> {
            if (btn == ButtonType.OK) {
                User user = SessionManager.getInstance().getCurrentUser();
                Long userId = user != null ? user.getId() : 1L;
                try {
                    reportService.deleteReport(selected.id(), userId);
                    loadReportsAsync();
                } catch (Exception e) {
                    log.error("Failed to delete report", e);
                }
            }
        });
    }

    @FXML
    public void onRefresh() {
        loadScansAsync();
        loadReportsAsync();
    }

    private void openFile(Path path) {
        if (path == null || !Files.exists(path)) {
            updateStatus("File not found on disk: " + path, true);
            return;
        }
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
                Desktop.getDesktop().open(path.toFile());
            } else {
                // Fallback process dispatch
                new ProcessBuilder("cmd", "/c", "start", "", path.toAbsolutePath().toString()).start();
            }
        } catch (Exception e) {
            log.warn("Could not launch default viewer: {}", e.getMessage());
            updateStatus("Report saved at: " + path.toAbsolutePath(), false);
        }
    }

    private void openFolder(Path folder) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
                Desktop.getDesktop().open(folder.toFile());
            } else {
                new ProcessBuilder("explorer.exe", folder.toAbsolutePath().toString()).start();
            }
        } catch (Exception e) {
            log.warn("Could not open directory: {}", e.getMessage());
        }
    }

    private void setGeneratingState(boolean generating) {
        if (btnGenerateReport != null) btnGenerateReport.setDisable(generating);
        if (pbGenerating != null) pbGenerating.setVisible(generating);
    }

    private void updateStatus(String message, boolean isError) {
        Runnable r = () -> {
            if (lblGenerationStatus != null) {
                lblGenerationStatus.setText(message);
                lblGenerationStatus.setStyle(isError ? "-fx-font-size: 13px; -fx-text-fill: #DC2626;" : "-fx-font-size: 13px; -fx-text-fill: #16A34A;");
            }
        };
        if (Platform.isFxApplicationThread()) {
            r.run();
        } else {
            Platform.runLater(r);
        }
    }
}
