package com.webshield.ui.controllers;

import com.webshield.api.dto.ApiFindingDto;
import com.webshield.api.dto.ApiScanComparisonDto;
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
 * Controller for differential analysis, regression detection, and fixed vulnerability verification between scans.
 */
@Component
@Scope("prototype")
public class ApiScanComparisonController {

    private static final Logger log = LoggerFactory.getLogger(ApiScanComparisonController.class);

    @FXML private ComboBox<ApiScanDto> cbScanA;
    @FXML private ComboBox<ApiScanDto> cbScanB;
    @FXML private Button btnCompare;
    @FXML private Label lblComparisonStatus;

    // Diff Metric Cards
    @FXML private Label lblNewFindings;
    @FXML private Label lblResolvedFindings;
    @FXML private Label lblPersistentFindings;
    @FXML private Label lblCoverageDelta;
    @FXML private Label lblDurationDelta;

    // Regressions Table (New findings in B)
    @FXML private TableView<ApiFindingDto> tableNewFindings;
    @FXML private TableColumn<ApiFindingDto, String> colNewSev;
    @FXML private TableColumn<ApiFindingDto, String> colNewTitle;
    @FXML private TableColumn<ApiFindingDto, String> colNewMethod;
    @FXML private TableColumn<ApiFindingDto, String> colNewEndpoint;
    @FXML private TableColumn<ApiFindingDto, String> colNewOwasp;

    // Resolved Table (Fixed findings from A)
    @FXML private TableView<ApiFindingDto> tableResolvedFindings;
    @FXML private TableColumn<ApiFindingDto, String> colResSev;
    @FXML private TableColumn<ApiFindingDto, String> colResTitle;
    @FXML private TableColumn<ApiFindingDto, String> colResMethod;
    @FXML private TableColumn<ApiFindingDto, String> colResEndpoint;
    @FXML private TableColumn<ApiFindingDto, String> colResOwasp;

    // Persistent Table (Present in both A and B)
    @FXML private TableView<ApiFindingDto> tablePersistentFindings;
    @FXML private TableColumn<ApiFindingDto, String> colPerSev;
    @FXML private TableColumn<ApiFindingDto, String> colPerTitle;
    @FXML private TableColumn<ApiFindingDto, String> colPerMethod;
    @FXML private TableColumn<ApiFindingDto, String> colPerEndpoint;
    @FXML private TableColumn<ApiFindingDto, String> colPerOwasp;
    @FXML private Label lblPersistentTableCount;

    private final ApiPersistenceService persistenceService;
    private Long preselectedScanAId;
    private Long preselectedScanBId;

    public ApiScanComparisonController() {
        this(SpringContext.getBean(ApiPersistenceService.class));
    }

    public ApiScanComparisonController(ApiPersistenceService persistenceService) {
        this.persistenceService = persistenceService;
    }

    @FXML
    public void initialize() {
        configureTables();
        configureCombos();
        loadScansAsync();
    }

    private void configureTables() {
        if (colNewSev != null) colNewSev.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().severity()));
        if (colNewTitle != null) colNewTitle.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().title()));
        if (colNewMethod != null) colNewMethod.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().httpMethod()));
        if (colNewEndpoint != null) colNewEndpoint.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().endpointPath()));
        if (colNewOwasp != null) colNewOwasp.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().owaspCategory() != null ? d.getValue().owaspCategory() : "—"));

        if (colResSev != null) colResSev.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().severity()));
        if (colResTitle != null) colResTitle.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().title()));
        if (colResMethod != null) colResMethod.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().httpMethod()));
        if (colResEndpoint != null) colResEndpoint.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().endpointPath()));
        if (colResOwasp != null) colResOwasp.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().owaspCategory() != null ? d.getValue().owaspCategory() : "—"));

        if (colPerSev != null) colPerSev.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().severity()));
        if (colPerTitle != null) colPerTitle.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().title()));
        if (colPerMethod != null) colPerMethod.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().httpMethod()));
        if (colPerEndpoint != null) colPerEndpoint.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().endpointPath()));
        if (colPerOwasp != null) colPerOwasp.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().owaspCategory() != null ? d.getValue().owaspCategory() : "—"));
    }

    private void configureCombos() {
        StringConverter<ApiScanDto> converter = new StringConverter<>() {
            @Override
            public String toString(ApiScanDto s) {
                return s != null ? "#" + s.id() + " - " + s.scanName() + " (" + s.totalFindings() + " findings)" : "";
            }

            @Override
            public ApiScanDto fromString(String string) {
                return null;
            }
        };

        if (cbScanA != null) cbScanA.setConverter(converter);
        if (cbScanB != null) cbScanB.setConverter(converter);
    }

    public void setPreselectedScans(Long scanAId, Long scanBId) {
        this.preselectedScanAId = scanAId;
        this.preselectedScanBId = scanBId;
        selectPreselected();
    }

    private void selectPreselected() {
        if (cbScanA != null && cbScanA.getItems() != null && preselectedScanAId != null) {
            cbScanA.getItems().stream()
                    .filter(s -> s.id().equals(preselectedScanAId))
                    .findFirst()
                    .ifPresent(cbScanA::setValue);
        }
        if (cbScanB != null && cbScanB.getItems() != null && preselectedScanBId != null) {
            cbScanB.getItems().stream()
                    .filter(s -> s.id().equals(preselectedScanBId))
                    .findFirst()
                    .ifPresent(cbScanB::setValue);
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
                if (cbScanA != null) cbScanA.setItems(FXCollections.observableArrayList(scans));
                if (cbScanB != null) cbScanB.setItems(FXCollections.observableArrayList(scans));

                selectPreselected();

                if (preselectedScanAId == null && scans.size() >= 2) {
                    if (cbScanA != null) cbScanA.getSelectionModel().select(1);
                    if (cbScanB != null) cbScanB.getSelectionModel().select(0);
                }
            }
        };
        Thread thread = new Thread(task, "load-comparison-scans");
        thread.setDaemon(true);
        thread.start();
    }

    @FXML
    public void onCompareScans() {
        ApiScanDto scanA = cbScanA != null ? cbScanA.getValue() : null;
        ApiScanDto scanB = cbScanB != null ? cbScanB.getValue() : null;

        if (scanA == null || scanB == null) {
            if (lblComparisonStatus != null) lblComparisonStatus.setText("Please select both Scan A and Scan B.");
            return;
        }

        if (scanA.id().equals(scanB.id())) {
            if (lblComparisonStatus != null) lblComparisonStatus.setText("Scan A and Scan B must be distinct scans.");
            return;
        }

        User user = SessionManager.getInstance().getCurrentUser();
        Long userId = user != null ? user.getId() : 1L;

        Task<ApiScanComparisonDto> task = new Task<>() {
            @Override
            protected ApiScanComparisonDto call() {
                return persistenceService.compareScans(scanA.id(), scanB.id(), userId);
            }

            @Override
            protected void succeeded() {
                ApiScanComparisonDto comp = getValue();
                renderComparison(comp);
            }

            @Override
            protected void failed() {
                log.error("Failed to compare scans", getException());
                if (lblComparisonStatus != null) {
                    lblComparisonStatus.setText("Comparison failed: " + getException().getMessage());
                }
            }
        };
        Thread thread = new Thread(task, "compare-scans-worker");
        thread.setDaemon(true);
        thread.start();
    }

    private void renderComparison(ApiScanComparisonDto comp) {
        if (comp == null) return;
        if (lblComparisonStatus != null) {
            lblComparisonStatus.setText(String.format("Comparison completed: %d new regressions, %d resolved, %d persistent.",
                    comp.newFindingsCount(), comp.resolvedFindingsCount(), comp.persistentFindingsCount()));
        }

        if (lblNewFindings != null) lblNewFindings.setText("+" + comp.newFindingsCount());
        if (lblResolvedFindings != null) lblResolvedFindings.setText("-" + comp.resolvedFindingsCount());
        if (lblPersistentFindings != null) lblPersistentFindings.setText(String.valueOf(comp.persistentFindingsCount()));

        if (lblCoverageDelta != null) {
            String sign = comp.coverageDifference() >= 0 ? "+" : "";
            lblCoverageDelta.setText(sign + Math.round(comp.coverageDifference() * 10.0) / 10.0 + "%");
        }
        if (lblDurationDelta != null) {
            String sign = comp.durationDifferenceMs() >= 0 ? "+" : "";
            lblDurationDelta.setText(sign + (comp.durationDifferenceMs() / 1000.0) + "s");
        }

        if (tableNewFindings != null) {
            tableNewFindings.setItems(FXCollections.observableArrayList(comp.newFindings()));
        }
        if (tableResolvedFindings != null) {
            tableResolvedFindings.setItems(FXCollections.observableArrayList(comp.resolvedFindings()));
        }
        if (tablePersistentFindings != null) {
            tablePersistentFindings.setItems(FXCollections.observableArrayList(
                    comp.persistentFindings() != null ? comp.persistentFindings() : List.of()));
        }
        if (lblPersistentTableCount != null) {
            lblPersistentTableCount.setText((comp.persistentFindings() != null ? comp.persistentFindings().size() : 0) + " findings");
        }
    }
}
