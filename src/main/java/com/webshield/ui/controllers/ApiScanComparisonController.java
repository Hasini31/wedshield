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

    @FXML private ComboBox<ApiProject> cbProject;
    @FXML private Label lblProjectScanCount;
    @FXML private ComboBox<ApiScanDto> cbScanA;
    @FXML private ComboBox<ApiScanDto> cbScanB;
    @FXML private Button btnSwap;
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
    private final ApiProjectService projectService;
    private Long preselectedScanAId;
    private Long preselectedScanBId;
    private boolean backgroundLoadingEnabled = true;

    private final List<ApiScanDto> currentProjectScans = new java.util.ArrayList<>();
    private boolean updatingScanCombos = false;

    public ApiScanComparisonController() {
        this(SpringContext.getBean(ApiPersistenceService.class),
             SpringContext.getBean(ApiProjectService.class));
    }

    public ApiScanComparisonController(ApiPersistenceService persistenceService) {
        this(persistenceService, SpringContext.getBean(ApiProjectService.class));
    }

    public ApiScanComparisonController(ApiPersistenceService persistenceService, ApiProjectService projectService) {
        this.persistenceService = persistenceService;
        this.projectService = projectService != null ? projectService : SpringContext.getBean(ApiProjectService.class);
    }

    public void setBackgroundLoadingEnabled(boolean enabled) {
        this.backgroundLoadingEnabled = enabled;
    }

    @FXML
    public void initialize() {
        configureTables();
        configureCombos();
        loadProjectsAsync();
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
        if (cbProject != null) {
            StringConverter<ApiProject> projectConverter = new StringConverter<>() {
                @Override
                public String toString(ApiProject p) {
                    if (p == null) return "";
                    String fmt = p.getSpecFormat() != null ? p.getSpecFormat().name() : "OpenAPI";
                    return p.getName() + " (" + fmt + ")";
                }

                @Override
                public ApiProject fromString(String string) {
                    return null;
                }
            };
            cbProject.setConverter(projectConverter);

            javafx.util.Callback<ListView<ApiProject>, ListCell<ApiProject>> projectCellFactory = lv -> new ListCell<>() {
                @Override
                protected void updateItem(ApiProject item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) {
                        setText(null);
                    } else {
                        String fmt = item.getSpecFormat() != null ? item.getSpecFormat().name() : "OpenAPI";
                        setText(item.getName() + " (" + fmt + ")");
                    }
                }
            };
            cbProject.setCellFactory(projectCellFactory);
            cbProject.setButtonCell(new ListCell<>() {
                @Override
                protected void updateItem(ApiProject item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) {
                        setText(null);
                    } else {
                        String fmt = item.getSpecFormat() != null ? item.getSpecFormat().name() : "OpenAPI";
                        setText(item.getName() + " (" + fmt + ")");
                    }
                }
            });

            cbProject.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, newVal) -> {
                if (newVal != null) {
                    onProjectSelected(newVal);
                } else {
                    if (cbScanA != null) cbScanA.setItems(FXCollections.emptyObservableList());
                    if (cbScanB != null) cbScanB.setItems(FXCollections.emptyObservableList());
                    if (lblProjectScanCount != null) lblProjectScanCount.setText("");
                    if (lblComparisonStatus != null) lblComparisonStatus.setText("Select a target project to compare versions.");
                    if (btnCompare != null) btnCompare.setDisable(true);
                }
            });
        }

        java.time.format.DateTimeFormatter scanDateFmt = java.time.format.DateTimeFormatter.ofPattern("dd MMM HH:mm");
        StringConverter<ApiScanDto> scanConverter = new StringConverter<>() {
            @Override
            public String toString(ApiScanDto s) {
                if (s == null) return "";
                String date = s.createdAt() != null ? s.createdAt().format(scanDateFmt) : (s.startedAt() != null ? s.startedAt().format(scanDateFmt) : "");
                String dateStr = !date.isBlank() ? " [" + date + "]" : "";
                return "#" + s.id() + " - " + s.scanName() + dateStr + " (" + s.totalFindings() + " findings)";
            }

            @Override
            public ApiScanDto fromString(String string) {
                return null;
            }
        };

        javafx.util.Callback<ListView<ApiScanDto>, ListCell<ApiScanDto>> scanCellFactory = lv -> new ListCell<>() {
            @Override
            protected void updateItem(ApiScanDto item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                } else {
                    String date = item.createdAt() != null ? item.createdAt().format(scanDateFmt) : (item.startedAt() != null ? item.startedAt().format(scanDateFmt) : "");
                    String dateStr = !date.isBlank() ? " [" + date + "]" : "";
                    setText("#" + item.id() + " - " + item.scanName() + dateStr + " (" + item.totalFindings() + " findings)");
                }
            }
        };

        if (cbScanA != null) {
            cbScanA.setConverter(scanConverter);
            cbScanA.setCellFactory(scanCellFactory);
            cbScanA.setButtonCell(new ListCell<>() {
                @Override
                protected void updateItem(ApiScanDto item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) {
                        setText(null);
                    } else {
                        String date = item.createdAt() != null ? item.createdAt().format(scanDateFmt) : (item.startedAt() != null ? item.startedAt().format(scanDateFmt) : "");
                        String dateStr = !date.isBlank() ? " [" + date + "]" : "";
                        setText("#" + item.id() + " - " + item.scanName() + dateStr + " (" + item.totalFindings() + " findings)");
                    }
                }
            });
            cbScanA.valueProperty().addListener((obs, oldV, newV) -> onScanAChanged(newV));
        }

        if (cbScanB != null) {
            cbScanB.setConverter(scanConverter);
            cbScanB.setCellFactory(scanCellFactory);
            cbScanB.setButtonCell(new ListCell<>() {
                @Override
                protected void updateItem(ApiScanDto item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) {
                        setText(null);
                    } else {
                        String date = item.createdAt() != null ? item.createdAt().format(scanDateFmt) : (item.startedAt() != null ? item.startedAt().format(scanDateFmt) : "");
                        String dateStr = !date.isBlank() ? " [" + date + "]" : "";
                        setText("#" + item.id() + " - " + item.scanName() + dateStr + " (" + item.totalFindings() + " findings)");
                    }
                }
            });
            cbScanB.valueProperty().addListener((obs, oldV, newV) -> onScanBChanged(newV));
        }
    }

    private void onScanAChanged(ApiScanDto newA) {
        if (updatingScanCombos || newA == null) return;
        ApiScanDto curB = cbScanB != null ? cbScanB.getValue() : null;
        applyMutualExclusion(newA, curB);
        Platform.runLater(this::onCompareScans);
    }

    private void onScanBChanged(ApiScanDto newB) {
        if (updatingScanCombos || newB == null) return;
        ApiScanDto curA = cbScanA != null ? cbScanA.getValue() : null;
        applyMutualExclusion(curA, newB);
        Platform.runLater(this::onCompareScans);
    }

    @FXML
    public void onSwapScans() {
        if (cbScanA == null || cbScanB == null) return;
        ApiScanDto a = cbScanA.getValue();
        ApiScanDto b = cbScanB.getValue();
        if (a == null || b == null || a.id().equals(b.id())) return;
        applyMutualExclusion(b, a);
        Platform.runLater(this::onCompareScans);
    }

    private void applyMutualExclusion(ApiScanDto selectedA, ApiScanDto selectedB) {
        if (currentProjectScans.isEmpty()) return;
        updatingScanCombos = true;
        try {
            // Options for Scan A: all scans except selectedB
            List<ApiScanDto> itemsA = currentProjectScans.stream()
                    .filter(s -> selectedB == null || !s.id().equals(selectedB.id()))
                    .toList();

            // Options for Scan B: all scans except selectedA
            List<ApiScanDto> itemsB = currentProjectScans.stream()
                    .filter(s -> selectedA == null || !s.id().equals(selectedA.id()))
                    .toList();

            if (cbScanA != null) {
                cbScanA.setItems(FXCollections.observableArrayList(itemsA));
                if (selectedA != null && itemsA.stream().anyMatch(s -> s.id().equals(selectedA.id()))) {
                    cbScanA.setValue(selectedA);
                } else if (!itemsA.isEmpty()) {
                    cbScanA.setValue(itemsA.get(0));
                }
            }

            if (cbScanB != null) {
                cbScanB.setItems(FXCollections.observableArrayList(itemsB));
                if (selectedB != null && itemsB.stream().anyMatch(s -> s.id().equals(selectedB.id()))) {
                    cbScanB.setValue(selectedB);
                } else if (!itemsB.isEmpty()) {
                    cbScanB.setValue(itemsB.get(0));
                }
            }

            onScanSelectionChanged();
        } finally {
            updatingScanCombos = false;
        }
    }

    private void onScanSelectionChanged() {
        ApiScanDto scanA = cbScanA != null ? cbScanA.getValue() : null;
        ApiScanDto scanB = cbScanB != null ? cbScanB.getValue() : null;

        if (scanA == null || scanB == null) {
            if (lblComparisonStatus != null) lblComparisonStatus.setText("Select both Scan A and Scan B to compare.");
            if (btnCompare != null) btnCompare.setDisable(true);
            return;
        }

        if (scanA.id().equals(scanB.id())) {
            if (lblComparisonStatus != null) {
                lblComparisonStatus.setText("Scan A and Scan B are the same scan (#" + scanA.id() + "). Please choose two distinct versions to compare.");
            }
            if (btnCompare != null) btnCompare.setDisable(true);
            return;
        }

        if (btnCompare != null) btnCompare.setDisable(false);
        if (lblComparisonStatus != null) {
            lblComparisonStatus.setText("Comparing Scan #" + scanA.id() + " vs Scan #" + scanB.id() + ".");
        }
    }

    public void setPreselectedScans(Long scanAId, Long scanBId) {
        this.preselectedScanAId = scanAId;
        this.preselectedScanBId = scanBId;
        if (scanAId != null && persistenceService != null && cbProject != null && cbProject.getItems() != null && !cbProject.getItems().isEmpty()) {
            User user = SessionManager.getInstance().getCurrentUser();
            Long userId = user != null ? user.getId() : 1L;
            persistenceService.getScanById(scanAId, userId).ifPresent(s -> {
                cbProject.getItems().stream()
                        .filter(p -> p.getId() != null && p.getId().equals(s.apiProjectId()))
                        .findFirst()
                        .ifPresent(p -> {
                            cbProject.getSelectionModel().select(p);
                            cbProject.setValue(p);
                        });
            });
        } else {
            selectPreselected();
        }
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

    public void loadProjectsAsync() {
        if (cbProject == null) {
            // Fallback for tests that do not inject cbProject
            loadScansAsync();
            return;
        }

        User user = SessionManager.getInstance().getCurrentUser();
        Long userId = user != null ? user.getId() : 1L;

        Task<List<ApiProject>> task = new Task<>() {
            @Override
            protected List<ApiProject> call() {
                List<ApiProject> projects = new java.util.ArrayList<>();
                if (projectService != null) {
                    try {
                        projects.addAll(projectService.getProjectsForCurrentUser());
                    } catch (Exception e) {
                        log.warn("Could not retrieve projects for current user: {}", e.getMessage());
                    }
                }

                // Fallback: If projectService returned empty, resolve projects from the user's scans
                if (projects.isEmpty() && persistenceService != null) {
                    try {
                        List<ApiScanDto> allScans = persistenceService.getScansForUser(userId);
                        java.util.Set<Long> pids = new java.util.LinkedHashSet<>();
                        for (ApiScanDto s : allScans) {
                            if (s.apiProjectId() != null) pids.add(s.apiProjectId());
                        }
                        for (Long pid : pids) {
                            if (projectService != null) {
                                projectService.getProject(pid).ifPresent(projects::add);
                            }
                        }
                    } catch (Exception e) {
                        log.warn("Fallback project lookup from scans failed: {}", e.getMessage());
                    }
                }
                return projects;
            }

            @Override
            protected void succeeded() {
                List<ApiProject> projects = getValue();
                if (cbProject != null) {
                    cbProject.setItems(FXCollections.observableArrayList(projects));
                    if (!projects.isEmpty()) {
                        ApiProject targetToSelect = null;
                        if (preselectedScanAId != null && persistenceService != null) {
                            var scanOpt = persistenceService.getScanById(preselectedScanAId, userId);
                            if (scanOpt.isPresent()) {
                                Long targetPid = scanOpt.get().apiProjectId();
                                targetToSelect = projects.stream()
                                        .filter(p -> p.getId() != null && p.getId().equals(targetPid))
                                        .findFirst()
                                        .orElse(null);
                            }
                        }
                        if (targetToSelect == null) {
                            targetToSelect = projects.get(0);
                        }
                        cbProject.getSelectionModel().select(targetToSelect);
                        cbProject.setValue(targetToSelect);
                        onProjectSelected(targetToSelect);
                    } else {
                        if (lblComparisonStatus != null) {
                            lblComparisonStatus.setText("No target API projects found. Please import or add an API project first.");
                        }
                        if (btnCompare != null) btnCompare.setDisable(true);
                    }
                }
            }
        };

        if (backgroundLoadingEnabled) {
            Thread thread = new Thread(task, "load-comparison-projects");
            thread.setDaemon(true);
            thread.start();
        } else {
            if (projectService != null) {
                try {
                    List<ApiProject> projects = projectService.getProjectsForCurrentUser();
                    cbProject.setItems(FXCollections.observableArrayList(projects));
                    if (!projects.isEmpty()) {
                        ApiProject p = projects.get(0);
                        cbProject.getSelectionModel().select(p);
                        cbProject.setValue(p);
                        onProjectSelected(p);
                    }
                } catch (Exception ignored) {}
            }
        }
    }

    public void onProjectSelected(ApiProject project) {
        if (project == null) return;
        User user = SessionManager.getInstance().getCurrentUser();
        Long userId = user != null ? user.getId() : 1L;

        Task<List<ApiScanDto>> task = new Task<>() {
            @Override
            protected List<ApiScanDto> call() {
                List<ApiScanDto> scans = persistenceService != null
                        ? persistenceService.getScansForProject(project.getId(), userId)
                        : List.of();
                if (scans.isEmpty() && persistenceService != null) {
                    List<ApiScanDto> all = persistenceService.getScansForUser(userId);
                    scans = all.stream()
                            .filter(s -> project.getId() != null && project.getId().equals(s.apiProjectId()))
                            .toList();
                }
                return scans;
            }

            @Override
            protected void succeeded() {
                List<ApiScanDto> scans = getValue();
                populateScansForProject(scans);
            }
        };

        if (backgroundLoadingEnabled) {
            Thread thread = new Thread(task, "load-project-scans");
            thread.setDaemon(true);
            thread.start();
        } else {
            List<ApiScanDto> scans = persistenceService != null
                    ? persistenceService.getScansForProject(project.getId(), userId)
                    : List.of();
            if (scans.isEmpty() && persistenceService != null) {
                List<ApiScanDto> all = persistenceService.getScansForUser(userId);
                scans = all.stream()
                        .filter(s -> project.getId() != null && project.getId().equals(s.apiProjectId()))
                        .toList();
            }
            populateScansForProject(scans);
        }
    }

    private void populateScansForProject(List<ApiScanDto> scans) {
        currentProjectScans.clear();
        currentProjectScans.addAll(scans);

        if (scans.isEmpty()) {
            if (cbScanA != null) cbScanA.setItems(FXCollections.emptyObservableList());
            if (cbScanB != null) cbScanB.setItems(FXCollections.emptyObservableList());
            if (lblProjectScanCount != null) lblProjectScanCount.setText("0 scans recorded");
            if (lblComparisonStatus != null) lblComparisonStatus.setText("No scans found for this target. Run at least 2 scans to compare.");
            if (btnCompare != null) btnCompare.setDisable(true);
            return;
        }

        if (scans.size() == 1) {
            if (cbScanA != null) {
                cbScanA.setItems(FXCollections.observableArrayList(scans));
                cbScanA.setValue(scans.get(0));
            }
            if (cbScanB != null) cbScanB.setItems(FXCollections.emptyObservableList());
            if (lblProjectScanCount != null) lblProjectScanCount.setText("1 scan recorded (need at least 2)");
            if (lblComparisonStatus != null) lblComparisonStatus.setText("Only 1 scan recorded. At least 2 scans of this target are needed to detect regressions.");
            if (btnCompare != null) btnCompare.setDisable(true);
            return;
        }

        // 2 or more scans: auto-select Baseline (Scan A = older) and Comparison (Scan B = newer)
        if (lblProjectScanCount != null) lblProjectScanCount.setText(scans.size() + " scans available for differential analysis");
        if (btnCompare != null) btnCompare.setDisable(false);

        // Preselection handling
        ApiScanDto initialA;
        ApiScanDto initialB;

        if (preselectedScanAId != null) {
            initialA = scans.stream().filter(s -> s.id().equals(preselectedScanAId)).findFirst()
                    .orElse(scans.get(Math.min(1, scans.size() - 1)));
        } else {
            initialA = scans.get(Math.min(1, scans.size() - 1));
        }

        if (preselectedScanBId != null) {
            initialB = scans.stream().filter(s -> s.id().equals(preselectedScanBId)).findFirst()
                    .orElse(scans.get(0));
        } else {
            initialB = scans.get(0);
        }

        // Ensure distinct default pairing
        if (initialA.id().equals(initialB.id())) {
            for (ApiScanDto s : scans) {
                if (!s.id().equals(initialA.id())) {
                    initialB = s;
                    break;
                }
            }
        }

        applyMutualExclusion(initialA, initialB);

        // Auto-execute comparison so metrics and tables populate immediately
        Platform.runLater(this::onCompareScans);
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
        if (backgroundLoadingEnabled) {
            Thread thread = new Thread(task, "load-comparison-scans");
            thread.setDaemon(true);
            thread.start();
        } else {
            List<ApiScanDto> scans = persistenceService != null ? persistenceService.getScansForUser(userId) : List.of();
            if (cbScanA != null) cbScanA.setItems(FXCollections.observableArrayList(scans));
            if (cbScanB != null) cbScanB.setItems(FXCollections.observableArrayList(scans));
            selectPreselected();
        }
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

        if (scanA.apiProjectId() != null && scanB.apiProjectId() != null && !scanA.apiProjectId().equals(scanB.apiProjectId())) {
            if (lblComparisonStatus != null) {
                lblComparisonStatus.setText("Cannot compare scans from different targets. Both scans must belong to the same project.");
            }
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
