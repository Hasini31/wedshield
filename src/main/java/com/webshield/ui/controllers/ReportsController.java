package com.webshield.ui.controllers;

import com.webshield.assessment.models.Severity;
import com.webshield.auth.SessionManager;
import com.webshield.config.SpringContext;
import com.webshield.database.repositories.ScanRecord;
import com.webshield.findings.FindingClassifier;
import com.webshield.findings.FindingService;
import com.webshield.findings.FindingStatus;
import com.webshield.models.SecurityFinding;
import com.webshield.models.User;
import com.webshield.scan.ScanService;
import com.webshield.ui.dialogs.AiReportViewerDialog;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Controller for the Reports page (vulnerability findings master-detail inspector).
 * Supports website target and scan run filtering with dedicated Gemini AI Report generation.
 */
@Component
@Scope("prototype")
public class ReportsController {

    private static final Logger log = LoggerFactory.getLogger(ReportsController.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm");
    private static final DateTimeFormatter FMT_SCAN = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    // Top Selector Bar
    @FXML private ComboBox<String> cbWebsiteTarget;
    @FXML private ComboBox<String> cbScanRun;
    @FXML private Button btnGenerateAiReport;

    // Summary Cards
    @FXML private Label lblCardTotal;
    @FXML private Label lblCardTotalDesc;
    @FXML private Label lblCardCritical;
    @FXML private Label lblCardHigh;
    @FXML private Label lblCardMedium;
    @FXML private Label lblCardLow;
    @FXML private Label lblCardInfo;

    // Filters and Search
    @FXML private TextField tfSearch;
    @FXML private ComboBox<String> cbSeverityFilter;
    @FXML private ComboBox<String> cbCategoryFilter;
    @FXML private ComboBox<String> cbStatusFilter;
    @FXML private Label lblTotalFindingsText;

    // Table
    @FXML private TableView<SecurityFinding> tableFindings;
    @FXML private TableColumn<SecurityFinding, String> colSeverity;
    @FXML private TableColumn<SecurityFinding, String> colName;
    @FXML private TableColumn<SecurityFinding, String> colTarget;
    @FXML private TableColumn<SecurityFinding, String> colParam;
    @FXML private TableColumn<SecurityFinding, String> colConfidence;
    @FXML private TableColumn<SecurityFinding, String> colStatus;
    @FXML private TableColumn<SecurityFinding, String> colDetected;

    // Inspector Detail Pane
    @FXML private VBox detailContentBox;
    @FXML private VBox detailEmptyBox;
    @FXML private Label lblDetailSeverity;
    @FXML private Label lblDetailCode;
    @FXML private Label lblDetailStatus;
    @FXML private Label lblDetailTitle;
    @FXML private Label lblDetailCategory;
    @FXML private Label lblDetailUrl;
    @FXML private Label lblDetailParam;
    @FXML private TextArea txtDetailDescription;
    @FXML private TextArea txtDetailImpact;
    @FXML private TextArea txtDetailEvidence;
    @FXML private TextArea txtDetailRemediation;
    @FXML private ComboBox<FindingStatus> cbUpdateStatus;
    @FXML private Label lblStatusUpdated;

    private final FindingService findingService;
    private final ScanService scanService;

    private final ObservableList<SecurityFinding> masterList = FXCollections.observableArrayList();
    private FilteredList<SecurityFinding> filteredList;

    private final List<ScanRecord> userScans = new ArrayList<>();
    private final Map<String, ScanRecord> scanItemMap = new LinkedHashMap<>();

    private Long filterScanId = null;
    private String selectedWebsite = "All Websites";
    private boolean updatingCombos = false;

    public ReportsController() {
        this(SpringContext.getBean(FindingService.class), SpringContext.getBean(ScanService.class));
    }

    public ReportsController(FindingService findingService) {
        this(findingService, SpringContext.getBean(ScanService.class));
    }

    public ReportsController(FindingService findingService, ScanService scanService) {
        this.findingService = findingService != null ? findingService : new FindingService();
        this.scanService = scanService != null ? scanService : new ScanService();
    }

    @FXML
    public void initialize() {
        configureTable();
        configureFilters();
        configureInspector();
        loadScansAndFindings();
    }

    private void configureTable() {
        colSeverity.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getSeverity().name()));
        colName.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getFindingName()));
        colTarget.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getAffectedUrl()));
        colParam.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().getAffectedParam() != null && !d.getValue().getAffectedParam().isBlank()
                        ? d.getValue().getAffectedParam() : "—"));
        colConfidence.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getConfidenceLevel().name()));
        colStatus.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getFindingStatus().getDisplayName()));
        colDetected.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().getDetectedAt() != null ? d.getValue().getDetectedAt().format(FMT) : "—"));

        tableFindings.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, newVal) -> {
            displayFindingDetail(newVal);
        });
    }

    private void configureFilters() {
        // Table search and toolbar filters
        cbSeverityFilter.setItems(FXCollections.observableArrayList(
                "All severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
        ));
        cbSeverityFilter.getSelectionModel().selectFirst();

        cbCategoryFilter.setItems(FXCollections.observableArrayList(
                "All categories", "Security Headers", "Cookies", "Input Reflection", "SQL Error Injection", "Input Validation"
        ));
        cbCategoryFilter.getSelectionModel().selectFirst();

        cbStatusFilter.setItems(FXCollections.observableArrayList(
                "All statuses", "Open", "Under Review", "Resolved", "False Positive"
        ));
        cbStatusFilter.getSelectionModel().selectFirst();

        filteredList = new FilteredList<>(masterList, p -> true);

        tfSearch.textProperty().addListener((obs, oldV, newV) -> applyFilters());
        cbSeverityFilter.valueProperty().addListener((obs, oldV, newV) -> applyFilters());
        cbCategoryFilter.valueProperty().addListener((obs, oldV, newV) -> applyFilters());
        cbStatusFilter.valueProperty().addListener((obs, oldV, newV) -> applyFilters());

        tableFindings.setItems(filteredList);

        // Website and Scan Run selector listeners
        if (cbWebsiteTarget != null) {
            cbWebsiteTarget.valueProperty().addListener((obs, oldV, newV) -> {
                if (updatingCombos || newV == null) return;
                onWebsiteSelected(newV);
            });
        }

        if (cbScanRun != null) {
            cbScanRun.valueProperty().addListener((obs, oldV, newV) -> {
                if (updatingCombos || newV == null) return;
                onScanRunSelected(newV);
            });
        }
    }

    private void configureInspector() {
        cbUpdateStatus.setItems(FXCollections.observableArrayList(FindingStatus.values()));
        cbUpdateStatus.getSelectionModel().select(FindingStatus.OPEN);
    }

    private void onWebsiteSelected(String website) {
        selectedWebsite = website;
        updatingCombos = true;
        try {
            populateScanRunCombo(website);
        } finally {
            updatingCombos = false;
        }

        // Auto-select the first scan item or all scans
        if (cbScanRun != null && !cbScanRun.getItems().isEmpty()) {
            cbScanRun.getSelectionModel().selectFirst();
            onScanRunSelected(cbScanRun.getValue());
        } else {
            filterScanId = null;
            applyFilters();
        }
    }

    private void populateScanRunCombo(String website) {
        if (cbScanRun == null) return;
        scanItemMap.clear();

        List<ScanRecord> matches;
        if (website == null || website.equals("All Websites")) {
            matches = new ArrayList<>(userScans);
        } else {
            matches = userScans.stream()
                    .filter(s -> s.getWebsiteName() != null && s.getWebsiteName().equalsIgnoreCase(website))
                    .collect(Collectors.toList());
        }

        ObservableList<String> items = FXCollections.observableArrayList();
        String allOption = (website == null || website.equals("All Websites"))
                ? "All Scans (" + matches.size() + " total)"
                : "All Scans for " + website + " (" + matches.size() + ")";
        items.add(allOption);

        for (ScanRecord r : matches) {
            String dateStr = r.getStartedAt() != null
                    ? r.getStartedAt().format(FMT_SCAN)
                    : (r.getCreatedAt() != null ? r.getCreatedAt().format(FMT_SCAN) : "Unknown Date");
            String label = "Scan #" + r.getId() + " — " + dateStr + " (" + r.getFindingsCount() + " findings)";
            items.add(label);
            scanItemMap.put(label, r);
        }

        cbScanRun.setItems(items);
    }

    private void onScanRunSelected(String selectedLabel) {
        if (selectedLabel == null) return;

        if (scanItemMap.containsKey(selectedLabel)) {
            ScanRecord r = scanItemMap.get(selectedLabel);
            filterScanId = r.getId();
            if (lblCardTotalDesc != null) {
                lblCardTotalDesc.setText("Scan #" + r.getId() + " (" + r.getWebsiteName() + ")");
            }
            if (btnGenerateAiReport != null) {
                btnGenerateAiReport.setText("🤖 Generate AI Report for Scan #" + r.getId());
            }
        } else {
            filterScanId = null;
            if (lblCardTotalDesc != null) {
                if (selectedWebsite != null && !selectedWebsite.equals("All Websites")) {
                    lblCardTotalDesc.setText("Across all scans for " + selectedWebsite);
                } else {
                    lblCardTotalDesc.setText("Across all active scans");
                }
            }
            if (btnGenerateAiReport != null) {
                btnGenerateAiReport.setText("🤖 Generate AI Security Report");
            }
        }

        applyFilters();
    }

    private void applyFilters() {
        String search = tfSearch.getText();
        String severity = cbSeverityFilter.getValue();
        String category = cbCategoryFilter.getValue();
        String status = cbStatusFilter.getValue();

        // Compute website-specific scan IDs when a website is selected but no specific scan is picked
        Set<Long> websiteScanIds = null;
        if (filterScanId == null && selectedWebsite != null && !selectedWebsite.equals("All Websites")) {
            websiteScanIds = userScans.stream()
                    .filter(s -> s.getWebsiteName() != null && s.getWebsiteName().equalsIgnoreCase(selectedWebsite))
                    .map(ScanRecord::getId)
                    .collect(Collectors.toSet());
        }

        final Set<Long> finalWebsiteScanIds = websiteScanIds;

        filteredList.setPredicate(finding -> {
            // Specific Scan ID filter
            if (filterScanId != null) {
                if (finding.getScanId() != filterScanId) {
                    return false;
                }
            } else if (finalWebsiteScanIds != null) {
                if (!finalWebsiteScanIds.contains(finding.getScanId())) {
                    return false;
                }
            }

            // Search text
            if (search != null && !search.isBlank()) {
                String term = search.toLowerCase().trim();
                boolean matchesName = finding.getFindingName() != null && finding.getFindingName().toLowerCase().contains(term);
                boolean matchesUrl = finding.getAffectedUrl() != null && finding.getAffectedUrl().toLowerCase().contains(term);
                boolean matchesParam = finding.getAffectedParam() != null && finding.getAffectedParam().toLowerCase().contains(term);
                if (!matchesName && !matchesUrl && !matchesParam) {
                    return false;
                }
            }

            // Severity
            if (severity != null && !severity.equals("All severities")) {
                if (!finding.getSeverity().name().equalsIgnoreCase(severity)) {
                    return false;
                }
            }

            // Category
            if (category != null && !category.equals("All categories")) {
                if (finding.getCategory() == null || !finding.getCategory().toLowerCase().contains(category.toLowerCase())) {
                    return false;
                }
            }

            // Status
            if (status != null && !status.equals("All statuses")) {
                if (!finding.getFindingStatus().getDisplayName().equalsIgnoreCase(status)) {
                    return false;
                }
            }

            return true;
        });

        updateSummaryCards();
    }

    private void updateSummaryCards() {
        int total = filteredList.size();
        if (lblTotalFindingsText != null) {
            lblTotalFindingsText.setText(total + (total == 1 ? " finding" : " findings"));
        }

        Map<Severity, Long> counts = FindingClassifier.groupFindingsBySeverity(filteredList);
        lblCardTotal.setText(String.valueOf(total));
        lblCardCritical.setText(String.valueOf(counts.getOrDefault(Severity.CRITICAL, 0L)));
        lblCardHigh.setText(String.valueOf(counts.getOrDefault(Severity.HIGH, 0L)));
        lblCardMedium.setText(String.valueOf(counts.getOrDefault(Severity.MEDIUM, 0L)));
        lblCardLow.setText(String.valueOf(counts.getOrDefault(Severity.LOW, 0L)));
        lblCardInfo.setText(String.valueOf(counts.getOrDefault(Severity.INFORMATIONAL, 0L)));
    }

    public void filterByScanId(long scanId) {
        this.filterScanId = scanId;
        syncScanSelection(scanId);
        applyFilters();
    }

    private void syncScanSelection(long scanId) {
        if (userScans.isEmpty() || cbWebsiteTarget == null || cbScanRun == null) return;

        ScanRecord target = userScans.stream().filter(s -> s.getId() == scanId).findFirst().orElse(null);
        if (target == null) return;

        updatingCombos = true;
        try {
            if (target.getWebsiteName() != null) {
                selectedWebsite = target.getWebsiteName();
                cbWebsiteTarget.getSelectionModel().select(target.getWebsiteName());
            }
            populateScanRunCombo(selectedWebsite);

            // Find matching scan label in scanItemMap
            for (Map.Entry<String, ScanRecord> entry : scanItemMap.entrySet()) {
                if (entry.getValue().getId() == scanId) {
                    cbScanRun.getSelectionModel().select(entry.getKey());
                    if (lblCardTotalDesc != null) {
                        lblCardTotalDesc.setText("Scan #" + scanId + " (" + target.getWebsiteName() + ")");
                    }
                    if (btnGenerateAiReport != null) {
                        btnGenerateAiReport.setText("🤖 Generate AI Report for Scan #" + scanId);
                    }
                    break;
                }
            }
        } finally {
            updatingCombos = false;
        }
    }

    @FXML
    private void onGenerateAiReport() {
        Stage stage = (Stage) tableFindings.getScene().getWindow();

        if (filterScanId != null && filterScanId > 0) {
            AiReportViewerDialog.show(filterScanId, stage);
            return;
        }

        SecurityFinding selected = tableFindings.getSelectionModel().getSelectedItem();
        if (selected != null && selected.getScanId() > 0) {
            AiReportViewerDialog.show(selected.getScanId(), stage);
            return;
        }

        // If a website is selected, see if there's a scan available to run
        if (!scanItemMap.isEmpty()) {
            ScanRecord latest = scanItemMap.values().iterator().next();
            Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
            confirm.setTitle("Generate AI Security Report");
            confirm.setHeaderText("No Specific Scan Selected");
            confirm.setContentText("Would you like to generate the AI Security Report for the latest scan (Scan #"
                    + latest.getId() + " - " + latest.getWebsiteName() + ")?");
            Optional<ButtonType> result = confirm.showAndWait();
            if (result.isPresent() && result.get() == ButtonType.OK) {
                AiReportViewerDialog.show(latest.getId(), stage);
            }
            return;
        }

        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Select Website Scan");
        alert.setHeaderText("No Scan Selected");
        alert.setContentText("Please select a website and scan date from the top dropdowns or click a finding in the table to generate an AI Security Report.");
        alert.showAndWait();
    }

    public void loadScansAndFindings() {
        User user = SessionManager.getInstance().getCurrentUser();
        if (user == null) return;

        Task<Void> task = new Task<>() {
            private List<ScanRecord> loadedScans;
            private List<SecurityFinding> loadedFindings;

            @Override
            protected Void call() {
                loadedScans = scanService.getUserScanHistory(user.getId());
                loadedFindings = findingService.getFindingsForUser(user.getId());
                return null;
            }

            @Override
            protected void succeeded() {
                userScans.clear();
                if (loadedScans != null) {
                    userScans.addAll(loadedScans);
                }

                masterList.setAll(loadedFindings != null ? loadedFindings : Collections.emptyList());

                // Populate cbWebsiteTarget
                if (cbWebsiteTarget != null) {
                    updatingCombos = true;
                    try {
                        Set<String> sites = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
                        for (ScanRecord r : userScans) {
                            if (r.getWebsiteName() != null && !r.getWebsiteName().isBlank()) {
                                sites.add(r.getWebsiteName());
                            }
                        }
                        ObservableList<String> siteItems = FXCollections.observableArrayList("All Websites");
                        siteItems.addAll(sites);
                        cbWebsiteTarget.setItems(siteItems);
                        cbWebsiteTarget.getSelectionModel().selectFirst();

                        populateScanRunCombo("All Websites");
                        if (cbScanRun != null && !cbScanRun.getItems().isEmpty()) {
                            cbScanRun.getSelectionModel().selectFirst();
                        }
                    } finally {
                        updatingCombos = false;
                    }
                }

                // If filterScanId was pre-set, synchronize
                if (filterScanId != null) {
                    syncScanSelection(filterScanId);
                }

                applyFilters();
            }

            @Override
            protected void failed() {
                log.error("Failed to load scans and findings", getException());
            }
        };

        Thread t = new Thread(task, "load-scans-and-findings-worker");
        t.setDaemon(true);
        t.start();
    }

    public void loadFindings() {
        loadScansAndFindings();
    }

    private void displayFindingDetail(SecurityFinding finding) {
        if (finding == null) {
            detailContentBox.setVisible(false);
            detailContentBox.setManaged(false);
            detailEmptyBox.setVisible(true);
            detailEmptyBox.setManaged(true);
            return;
        }

        detailEmptyBox.setVisible(false);
        detailEmptyBox.setManaged(false);
        detailContentBox.setVisible(true);
        detailContentBox.setManaged(true);

        lblDetailSeverity.setText(finding.getSeverity().name());
        lblDetailCode.setText(finding.getVulnerabilityCode() != null ? finding.getVulnerabilityCode() : "WS-GEN-001");
        lblDetailStatus.setText(finding.getFindingStatus().getDisplayName().toUpperCase());
        lblDetailTitle.setText(finding.getFindingName());
        lblDetailCategory.setText(finding.getCategory() != null ? finding.getCategory().toUpperCase() : "GENERAL");
        lblDetailUrl.setText(finding.getAffectedUrl());
        lblDetailParam.setText(finding.getAffectedParam() != null && !finding.getAffectedParam().isBlank()
                ? finding.getAffectedParam() : "Not parameter-specific");

        txtDetailDescription.setText(finding.getDescription() != null ? finding.getDescription() : "");
        txtDetailImpact.setText(finding.getDescription() != null ? "May allow unauthorized exploitation or leakage." : "");
        txtDetailEvidence.setText(finding.getEvidence() != null ? finding.getEvidence().getFormattedSummary() : "");
        txtDetailRemediation.setText(finding.getRemediation() != null ? finding.getRemediation() : "");

        cbUpdateStatus.getSelectionModel().select(finding.getFindingStatus());
        lblStatusUpdated.setText("");
    }

    @FXML
    private void onUpdateStatus() {
        SecurityFinding selected = tableFindings.getSelectionModel().getSelectedItem();
        FindingStatus newStatus = cbUpdateStatus.getValue();
        if (selected == null || newStatus == null) return;

        User user = SessionManager.getInstance().getCurrentUser();
        String username = user != null ? user.getFullName() : "Analyst";

        boolean ok = findingService.updateFindingStatus(selected.getId(), newStatus, username, "Status changed by analyst");
        if (ok) {
            selected.setFindingStatus(newStatus);
            lblDetailStatus.setText(newStatus.getDisplayName().toUpperCase());
            lblStatusUpdated.setText("Status updated to: " + newStatus.getDisplayName());
            tableFindings.refresh();
            updateSummaryCards();
        } else {
            lblStatusUpdated.setText("Failed to update finding status in database.");
        }
    }

    @FXML
    private void onMarkFalsePositive() {
        cbUpdateStatus.getSelectionModel().select(FindingStatus.FALSE_POSITIVE);
        onUpdateStatus();
    }

    @FXML
    private void onMarkResolved() {
        cbUpdateStatus.getSelectionModel().select(FindingStatus.RESOLVED);
        onUpdateStatus();
    }

    @FXML
    private void onRefresh() {
        loadScansAndFindings();
    }
}

