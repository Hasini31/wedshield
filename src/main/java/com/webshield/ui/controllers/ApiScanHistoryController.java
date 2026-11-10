package com.webshield.ui.controllers;

import com.webshield.api.dto.ApiScanDto;
import com.webshield.api.models.ApiProject;
import com.webshield.api.service.ApiPersistenceService;
import com.webshield.api.service.ApiProjectService;
import com.webshield.auth.SessionManager;
import com.webshield.config.SpringContext;
import com.webshield.models.User;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.util.StringConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Controller for managing and reviewing past API security scans, durations, findings, and lifecycles.
 */
@Component
@Scope("prototype")
public class ApiScanHistoryController {

    private static final Logger log = LoggerFactory.getLogger(ApiScanHistoryController.class);

    @FXML private ComboBox<ApiProject> cbProjectFilter;
    @FXML private TextField tfSearch;
    @FXML private Label lblScanCount;

    @FXML private TableView<ApiScanDto> tableScans;
    @FXML private TableColumn<ApiScanDto, String> colScanId;
    @FXML private TableColumn<ApiScanDto, String> colScanName;
    @FXML private TableColumn<ApiScanDto, String> colStatus;
    @FXML private TableColumn<ApiScanDto, String> colStartedAt;
    @FXML private TableColumn<ApiScanDto, String> colDuration;
    @FXML private TableColumn<ApiScanDto, String> colTests;
    @FXML private TableColumn<ApiScanDto, String> colRequests;
    @FXML private TableColumn<ApiScanDto, String> colFindings;

    @FXML private Button btnViewFindings;
    @FXML private Button btnViewExecutions;
    @FXML private Button btnCompare;
    @FXML private Button btnDeleteScan;

    private final ApiPersistenceService persistenceService;
    private final ApiProjectService apiProjectService;
    private final ObservableList<ApiScanDto> masterList = FXCollections.observableArrayList();
    private FilteredList<ApiScanDto> filteredList;
    private boolean backgroundLoadingEnabled = true;

    public ApiScanHistoryController() {
        this(SpringContext.getBean(ApiPersistenceService.class), SpringContext.getBean(ApiProjectService.class));
    }

    public ApiScanHistoryController(ApiPersistenceService persistenceService, ApiProjectService apiProjectService) {
        this.persistenceService = persistenceService;
        this.apiProjectService = apiProjectService != null ? apiProjectService : new ApiProjectService();
    }

    public void setBackgroundLoadingEnabled(boolean enabled) {
        this.backgroundLoadingEnabled = enabled;
    }

    public void setMasterList(List<ApiScanDto> scans) {
        this.backgroundLoadingEnabled = false;
        masterList.setAll(scans);
        applyFilters();
    }

    @FXML
    public void initialize() {
        configureTables();
        configureFilters();
        if (backgroundLoadingEnabled) {
            loadProjectsAndScans();
        }
    }

    private void configureTables() {
        if (colScanId != null) colScanId.setCellValueFactory(d -> new SimpleStringProperty("#" + d.getValue().id()));
        if (colScanName != null) colScanName.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().scanName()));
        if (colStatus != null) colStatus.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().status() != null ? d.getValue().status().name() : "PENDING"));
        if (colStartedAt != null) colStartedAt.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().startedAt() != null ? d.getValue().startedAt().toString().replace("T", " ") : "—"));
        if (colDuration != null) colDuration.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().durationMs() > 0 ? (d.getValue().durationMs() / 1000.0) + "s" : "—"));
        if (colTests != null) colTests.setCellValueFactory(d -> new SimpleStringProperty(
                String.valueOf(d.getValue().totalGeneratedTestCases())));
        if (colRequests != null) colRequests.setCellValueFactory(d -> new SimpleStringProperty(
                String.valueOf(d.getValue().totalExecutedRequests())));
        if (colFindings != null) colFindings.setCellValueFactory(d -> {
            ApiScanDto s = d.getValue();
            return new SimpleStringProperty(s.totalFindings() + " (" + s.criticalCount() + " Crit, " + s.highCount() + " High)");
        });

        // Disable buttons if nothing selected
        if (tableScans != null) {
            var selectedProp = tableScans.getSelectionModel().selectedItemProperty();
            if (btnViewFindings != null) btnViewFindings.disableProperty().bind(selectedProp.isNull());
            if (btnViewExecutions != null) btnViewExecutions.disableProperty().bind(selectedProp.isNull());
            if (btnCompare != null) btnCompare.disableProperty().bind(selectedProp.isNull());
            if (btnDeleteScan != null) btnDeleteScan.disableProperty().bind(selectedProp.isNull());
        }
    }

    private void configureFilters() {
        filteredList = new FilteredList<>(masterList, s -> true);

        if (tfSearch != null) {
            tfSearch.textProperty().addListener((obs, oldV, newV) -> applyFilters());
        }

        if (cbProjectFilter != null) {
            cbProjectFilter.setConverter(new StringConverter<>() {
                @Override
                public String toString(ApiProject p) {
                    return p != null ? p.getName() : "All Projects";
                }

                @Override
                public ApiProject fromString(String string) {
                    return null;
                }
            });

            cbProjectFilter.valueProperty().addListener((obs, oldV, selected) -> applyFilters());
        }

        if (tableScans != null) {
            tableScans.setItems(filteredList);
        }
    }

    private void applyFilters() {
        ApiProject project = cbProjectFilter != null ? cbProjectFilter.getValue() : null;
        String search = tfSearch != null ? tfSearch.getText() : null;
        String query = search != null ? search.trim().toLowerCase() : "";

        filteredList.setPredicate(s -> {
            if (project != null && !project.getId().equals(s.apiProjectId())) {
                return false;
            }
            if (query.isEmpty()) return true;
            boolean nameMatch = s.scanName() != null && s.scanName().toLowerCase().contains(query);
            boolean statusMatch = s.status() != null && s.status().name().toLowerCase().contains(query);
            return nameMatch || statusMatch;
        });

        if (lblScanCount != null) {
            lblScanCount.setText(filteredList.size() + " scans");
        }
    }

    public void loadProjectsAndScans() {
        User user = SessionManager.getInstance().getCurrentUser();
        Long userId = user != null ? user.getId() : 1L;

        Task<Void> task = new Task<>() {
            @Override
            protected Void call() {
                List<ApiProject> projects = apiProjectService.getProjectsForCurrentUser();
                List<ApiScanDto> scans = persistenceService != null ? persistenceService.getScansForUser(userId) : List.of();

                Platform.runLater(() -> {
                    if (cbProjectFilter != null) {
                        cbProjectFilter.setItems(FXCollections.observableArrayList(projects));
                    }
                    masterList.setAll(scans);
                    applyFilters();
                });
                return null;
            }
        };
        Thread thread = new Thread(task, "load-scan-history");
        thread.setDaemon(true);
        thread.start();
    }

    @FXML
    public void onRefresh() {
        loadProjectsAndScans();
    }

    @FXML
    public void onViewFindings() {
        ApiScanDto selected = tableScans != null ? tableScans.getSelectionModel().getSelectedItem() : null;
        if (selected != null && ShellController.getInstance() != null) {
            ShellController.getInstance().openApiFindingsForScan(selected.id());
        }
    }

    @FXML
    public void onViewExecutions() {
        ApiScanDto selected = tableScans != null ? tableScans.getSelectionModel().getSelectedItem() : null;
        if (selected != null && ShellController.getInstance() != null) {
            ShellController.getInstance().openApiExecutionsForScan(selected.id());
        }
    }

    @FXML
    public void onCompare() {
        ApiScanDto selected = tableScans != null ? tableScans.getSelectionModel().getSelectedItem() : null;
        if (selected != null && ShellController.getInstance() != null) {
            ShellController.getInstance().openApiComparisonFor(selected.id(), null);
        }
    }

    @FXML
    public void onDeleteScan() {
        ApiScanDto selected = tableScans != null ? tableScans.getSelectionModel().getSelectedItem() : null;
        if (selected == null || persistenceService == null) return;

        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle("Confirm Deletion");
        alert.setHeaderText("Delete API Scan #" + selected.id());
        alert.setContentText("Are you sure you want to delete scan '" + selected.scanName() + "' and all associated execution records and findings?");

        alert.showAndWait().ifPresent(btn -> {
            if (btn == ButtonType.OK) {
                User user = SessionManager.getInstance().getCurrentUser();
                Long userId = user != null ? user.getId() : 1L;
                try {
                    persistenceService.deleteScan(selected.id(), userId);
                    loadProjectsAndScans();
                } catch (Exception e) {
                    log.error("Failed to delete scan", e);
                }
            }
        });
    }
}
