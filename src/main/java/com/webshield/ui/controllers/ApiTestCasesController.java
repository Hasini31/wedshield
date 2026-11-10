package com.webshield.ui.controllers;

import com.webshield.api.dto.ApiScanDto;
import com.webshield.api.dto.ApiTestCaseResultDto;
import com.webshield.api.service.ApiPersistenceService;
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
import javafx.scene.layout.VBox;
import javafx.util.StringConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Controller for inspecting generated and mutated API test cases, categories, and mutation lineage.
 */
@Component
@Scope("prototype")
public class ApiTestCasesController {

    private static final Logger log = LoggerFactory.getLogger(ApiTestCasesController.class);

    @FXML private ComboBox<ApiScanDto> cbScans;
    @FXML private ComboBox<String> cbCategoryFilter;
    @FXML private TextField tfSearch;
    @FXML private Label lblTestCaseCount;

    @FXML private TableView<ApiTestCaseResultDto> tableTestCases;
    @FXML private TableColumn<ApiTestCaseResultDto, String> colTestCaseId;
    @FXML private TableColumn<ApiTestCaseResultDto, String> colMethod;
    @FXML private TableColumn<ApiTestCaseResultDto, String> colEndpoint;
    @FXML private TableColumn<ApiTestCaseResultDto, String> colCategory;
    @FXML private TableColumn<ApiTestCaseResultDto, String> colStrategy;
    @FXML private TableColumn<ApiTestCaseResultDto, String> colTarget;

    // Detail inspector
    @FXML private VBox paneDetails;
    @FXML private Label lblDetailTestId;
    @FXML private Label lblDetailCategory;
    @FXML private Label lblDetailMethod;
    @FXML private Label lblDetailEndpoint;
    @FXML private Label lblDetailStrategy;
    @FXML private Label lblDetailParent;
    @FXML private Label lblDetailTarget;
    @FXML private TextArea txtDetailDescription;

    private final ApiPersistenceService persistenceService;
    private final ObservableList<ApiTestCaseResultDto> masterList = FXCollections.observableArrayList();
    private FilteredList<ApiTestCaseResultDto> filteredList;
    private Long preselectedScanId;

    public ApiTestCasesController() {
        this(SpringContext.getBean(ApiPersistenceService.class));
    }

    public ApiTestCasesController(ApiPersistenceService persistenceService) {
        this.persistenceService = persistenceService;
    }

    @FXML
    public void initialize() {
        configureTables();
        configureFilters();
        loadScansAsync();
    }

    private void configureTables() {
        if (colTestCaseId != null) colTestCaseId.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().testCaseId()));
        if (colMethod != null) colMethod.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().httpMethod()));
        if (colEndpoint != null) colEndpoint.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().endpointIdentifier()));
        if (colCategory != null) colCategory.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().category()));
        if (colStrategy != null) colStrategy.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().strategy()));
        if (colTarget != null) colTarget.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().targetedProperty() != null ? d.getValue().targetedProperty() : "—"));

        if (tableTestCases != null) {
            tableTestCases.getSelectionModel().selectedItemProperty().addListener((obs, oldV, selected) -> displayDetails(selected));
        }
    }

    private void configureFilters() {
        filteredList = new FilteredList<>(masterList, tc -> true);

        if (cbCategoryFilter != null) {
            cbCategoryFilter.setItems(FXCollections.observableArrayList("ALL", "VALID", "INVALID", "BOUNDARY", "MUTATION"));
            cbCategoryFilter.setValue("ALL");
            cbCategoryFilter.valueProperty().addListener((obs, oldV, newV) -> applyFilters());
        }

        if (tfSearch != null) {
            tfSearch.textProperty().addListener((obs, oldV, newV) -> applyFilters());
        }

        if (tableTestCases != null) {
            tableTestCases.setItems(filteredList);
        }

        if (cbScans != null) {
            cbScans.setConverter(new StringConverter<>() {
                @Override
                public String toString(ApiScanDto scan) {
                    return scan != null ? "#" + scan.id() + " - " + scan.scanName() + " (" + scan.status() + ")" : "";
                }

                @Override
                public ApiScanDto fromString(String string) {
                    return null;
                }
            });

            cbScans.valueProperty().addListener((obs, oldV, selected) -> {
                if (selected != null) {
                    loadTestCasesForScan(selected.id());
                }
            });
        }
    }

    private void applyFilters() {
        String cat = cbCategoryFilter != null ? cbCategoryFilter.getValue() : "ALL";
        String search = tfSearch != null ? tfSearch.getText() : null;
        String query = search != null ? search.trim().toLowerCase() : "";

        filteredList.setPredicate(tc -> {
            boolean catMatches = "ALL".equalsIgnoreCase(cat)
                    || (tc.category() != null && tc.category().equalsIgnoreCase(cat));
            if (!catMatches) return false;

            if (query.isEmpty()) return true;
            boolean idMatches = tc.testCaseId() != null && tc.testCaseId().toLowerCase().contains(query);
            boolean epMatches = tc.endpointIdentifier() != null && tc.endpointIdentifier().toLowerCase().contains(query);
            boolean stratMatches = tc.strategy() != null && tc.strategy().toLowerCase().contains(query);
            boolean descMatches = tc.description() != null && tc.description().toLowerCase().contains(query);
            return idMatches || epMatches || stratMatches || descMatches;
        });

        if (lblTestCaseCount != null) {
            lblTestCaseCount.setText(filteredList.size() + " test cases");
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
        Thread thread = new Thread(task, "load-testcase-scans");
        thread.setDaemon(true);
        thread.start();
    }

    public void loadTestCasesForScan(Long scanId) {
        if (scanId == null || persistenceService == null) return;
        User user = SessionManager.getInstance().getCurrentUser();
        Long userId = user != null ? user.getId() : 1L;

        Task<List<ApiTestCaseResultDto>> task = new Task<>() {
            @Override
            protected List<ApiTestCaseResultDto> call() {
                return persistenceService.getTestCasesForScan(scanId, userId);
            }

            @Override
            protected void succeeded() {
                masterList.setAll(getValue());
                applyFilters();
                if (!masterList.isEmpty() && tableTestCases != null) {
                    tableTestCases.getSelectionModel().select(0);
                }
            }
        };
        Thread thread = new Thread(task, "load-testcases");
        thread.setDaemon(true);
        thread.start();
    }

    private void displayDetails(ApiTestCaseResultDto tc) {
        if (tc == null) {
            if (paneDetails != null) paneDetails.setVisible(false);
            return;
        }
        if (paneDetails != null) paneDetails.setVisible(true);

        if (lblDetailTestId != null) lblDetailTestId.setText(tc.testCaseId());
        if (lblDetailCategory != null) lblDetailCategory.setText(tc.category());
        if (lblDetailMethod != null) lblDetailMethod.setText(tc.httpMethod());
        if (lblDetailEndpoint != null) lblDetailEndpoint.setText(tc.endpointIdentifier());
        if (lblDetailStrategy != null) lblDetailStrategy.setText(tc.strategy());
        if (lblDetailParent != null) {
            lblDetailParent.setText(tc.parentTestCaseId() != null ? tc.parentTestCaseId() : "None (Root Case)");
        }
        if (lblDetailTarget != null) {
            lblDetailTarget.setText((tc.targetedProperty() != null ? tc.targetedProperty() : "General")
                    + (tc.targetedConstraint() != null ? " (" + tc.targetedConstraint() + ")" : ""));
        }
        if (txtDetailDescription != null) {
            txtDetailDescription.setText(tc.description() != null ? tc.description() : "No description provided.");
        }
    }
}

