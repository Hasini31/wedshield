package com.webshield.ui.controllers;

import com.webshield.assessment.models.Severity;
import com.webshield.auth.SessionManager;
import com.webshield.findings.FindingClassifier;
import com.webshield.findings.FindingService;
import com.webshield.findings.FindingStatus;
import com.webshield.models.SecurityFinding;
import com.webshield.models.User;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Controller for the Reports page (vulnerability findings master-detail inspector).
 */
@Component
@Scope("prototype")
public class ReportsController {

    private static final Logger log = LoggerFactory.getLogger(ReportsController.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm");

    // Summary Cards
    @FXML private Label lblCardTotal;
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
    private final ObservableList<SecurityFinding> masterList = FXCollections.observableArrayList();
    private FilteredList<SecurityFinding> filteredList;

    private Long filterScanId = null;

    public ReportsController() {
        this(com.webshield.config.SpringContext.getBean(FindingService.class));
    }

    public ReportsController(FindingService findingService) {
        this.findingService = findingService != null ? findingService : new FindingService();
    }

    @FXML
    public void initialize() {
        configureTable();
        configureFilters();
        configureInspector();
        loadFindings();
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
    }

    private void configureInspector() {
        cbUpdateStatus.setItems(FXCollections.observableArrayList(FindingStatus.values()));
        cbUpdateStatus.getSelectionModel().select(FindingStatus.OPEN);
    }

    private void applyFilters() {
        String search = tfSearch.getText();
        String severity = cbSeverityFilter.getValue();
        String category = cbCategoryFilter.getValue();
        String status = cbStatusFilter.getValue();

        filteredList.setPredicate(finding -> {
            // Scan ID filter if navigation came from scan history
            if (filterScanId != null && finding.getScanId() != filterScanId) {
                return false;
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
        applyFilters();
    }

    public void loadFindings() {
        User user = SessionManager.getInstance().getCurrentUser();
        if (user == null) return;

        Task<List<SecurityFinding>> task = new Task<>() {
            @Override
            protected List<SecurityFinding> call() {
                return findingService.getFindingsForUser(user.getId());
            }

            @Override
            protected void succeeded() {
                masterList.setAll(getValue());
                applyFilters();
            }

            @Override
            protected void failed() {
                log.error("Failed to load security findings", getException());
            }
        };

        Thread t = new Thread(task, "load-findings-worker");
        t.setDaemon(true);
        t.start();
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
        loadFindings();
    }
}
