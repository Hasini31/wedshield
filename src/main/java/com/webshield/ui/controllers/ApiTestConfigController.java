package com.webshield.ui.controllers;

import com.webshield.api.execution.ApiExecutionConfiguration;
import com.webshield.api.models.ApiProject;
import com.webshield.api.search.SearchConfiguration;
import com.webshield.api.service.ApiProjectService;
import com.webshield.config.SpringContext;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.util.StringConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;

/**
 * Controller for configuring API security scans, evolutionary search, and execution constraints.
 */
@Component
@Scope("prototype")
public class ApiTestConfigController {

    private static final Logger log = LoggerFactory.getLogger(ApiTestConfigController.class);

    @FXML private ComboBox<ApiProject> cbProjects;
    @FXML private TextField tfTargetBaseUrl;
    @FXML private Label lblValidationMsg;

    // Test Generation
    @FXML private CheckBox chkValidCases;
    @FXML private CheckBox chkInvalidCases;
    @FXML private CheckBox chkBoundaryCases;
    @FXML private Spinner<Integer> spCasesPerEndpoint;
    @FXML private Spinner<Integer> spSchemaDepth;

    // Input Mutation
    @FXML private CheckBox chkEnableMutation;
    @FXML private Spinner<Double> spMutationProbability;
    @FXML private Spinner<Integer> spMaxMutations;
    @FXML private CheckBox chkTypeMutations;
    @FXML private CheckBox chkBoundaryMutations;
    @FXML private CheckBox chkSecurityPayloads;
    @FXML private CheckBox chkStructuralMutations;

    // Evolutionary Search (MIO)
    @FXML private CheckBox chkEnableMio;
    @FXML private Spinner<Integer> spPopulationSize;
    @FXML private Spinner<Integer> spMaxGenerations;
    @FXML private Spinner<Integer> spEvaluationBudget;

    // Execution Safety Constraints
    @FXML private Spinner<Integer> spRequestTimeoutMs;
    @FXML private Spinner<Integer> spMaxResponseSizeBytes;
    @FXML private Spinner<Integer> spRateLimitRps;
    @FXML private Spinner<Integer> spConcurrency;
    @FXML private CheckBox chkAllowUnsafeMethods;

    private final ApiProjectService apiProjectService;
    private Long preselectedProjectId;

    public ApiTestConfigController() {
        this(SpringContext.getBean(ApiProjectService.class));
    }

    public ApiTestConfigController(ApiProjectService apiProjectService) {
        this.apiProjectService = apiProjectService != null ? apiProjectService : new ApiProjectService();
    }

    @FXML
    public void initialize() {
        setupSpinners();
        setupProjectCombo();
        resetToDefaults();
        loadProjectsAsync();
    }

    private void setupSpinners() {
        if (spCasesPerEndpoint != null) spCasesPerEndpoint.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 100, 10));
        if (spSchemaDepth != null) spSchemaDepth.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 10, 3));

        if (spMutationProbability != null) {
            SpinnerValueFactory.DoubleSpinnerValueFactory probFactory =
                    new SpinnerValueFactory.DoubleSpinnerValueFactory(0.05, 1.0, 0.35, 0.05);
            spMutationProbability.setValueFactory(probFactory);
        }
        if (spMaxMutations != null) spMaxMutations.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 10, 3));

        if (spPopulationSize != null) spPopulationSize.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(5, 100, 20));
        if (spMaxGenerations != null) spMaxGenerations.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(5, 200, 30));
        if (spEvaluationBudget != null) spEvaluationBudget.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(10, 1000, 100));

        if (spRequestTimeoutMs != null) spRequestTimeoutMs.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(500, 60000, 5000, 500));
        if (spMaxResponseSizeBytes != null) spMaxResponseSizeBytes.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(1024, 10485760, 1048576, 65536));
        if (spRateLimitRps != null) spRateLimitRps.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 100, 10));
        if (spConcurrency != null) spConcurrency.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 16, 2));
    }

    private void setupProjectCombo() {
        if (cbProjects == null) return;
        cbProjects.setConverter(new StringConverter<>() {
            @Override
            public String toString(ApiProject project) {
                return project != null ? project.getName() + " (" + project.getEndpointsCount() + " endpoints)" : "";
            }

            @Override
            public ApiProject fromString(String string) {
                return null;
            }
        });

        cbProjects.valueProperty().addListener((obs, oldV, selected) -> {
            if (selected != null && tfTargetBaseUrl != null) {
                if (selected.getSourceUrl() != null && selected.getSourceUrl().startsWith("http")) {
                    tfTargetBaseUrl.setText(selected.getSourceUrl());
                } else if (tfTargetBaseUrl.getText() == null || tfTargetBaseUrl.getText().isBlank()) {
                    tfTargetBaseUrl.setText("http://localhost:8080");
                }
            }
        });
    }

    public void setPreselectedProjectId(Long projectId) {
        this.preselectedProjectId = projectId;
        if (cbProjects != null && cbProjects.getItems() != null) {
            cbProjects.getItems().stream()
                    .filter(p -> p.getId().equals(projectId))
                    .findFirst()
                    .ifPresent(cbProjects::setValue);
        }
    }

    public void loadProjectsAsync() {
        Task<List<ApiProject>> task = new Task<>() {
            @Override
            protected List<ApiProject> call() {
                return apiProjectService.getProjectsForCurrentUser();
            }

            @Override
            protected void succeeded() {
                List<ApiProject> projects = getValue();
                if (cbProjects != null) {
                    cbProjects.setItems(FXCollections.observableArrayList(projects));
                    if (preselectedProjectId != null) {
                        setPreselectedProjectId(preselectedProjectId);
                    } else if (!projects.isEmpty()) {
                        cbProjects.getSelectionModel().select(0);
                    }
                }
            }

            @Override
            protected void failed() {
                log.error("Failed to load projects for scan configuration", getException());
            }
        };
        Thread thread = new Thread(task, "load-config-projects");
        thread.setDaemon(true);
        thread.start();
    }

    @FXML
    public void resetToDefaults() {
        if (lblValidationMsg != null) lblValidationMsg.setText("");

        if (chkValidCases != null) chkValidCases.setSelected(true);
        if (chkInvalidCases != null) chkInvalidCases.setSelected(true);
        if (chkBoundaryCases != null) chkBoundaryCases.setSelected(true);
        if (spCasesPerEndpoint != null) spCasesPerEndpoint.getValueFactory().setValue(10);
        if (spSchemaDepth != null) spSchemaDepth.getValueFactory().setValue(3);

        if (chkEnableMutation != null) chkEnableMutation.setSelected(true);
        if (spMutationProbability != null) spMutationProbability.getValueFactory().setValue(0.35);
        if (spMaxMutations != null) spMaxMutations.getValueFactory().setValue(3);
        if (chkTypeMutations != null) chkTypeMutations.setSelected(true);
        if (chkBoundaryMutations != null) chkBoundaryMutations.setSelected(true);
        if (chkSecurityPayloads != null) chkSecurityPayloads.setSelected(true);
        if (chkStructuralMutations != null) chkStructuralMutations.setSelected(true);

        if (chkEnableMio != null) chkEnableMio.setSelected(true);
        if (spPopulationSize != null) spPopulationSize.getValueFactory().setValue(20);
        if (spMaxGenerations != null) spMaxGenerations.getValueFactory().setValue(30);
        if (spEvaluationBudget != null) spEvaluationBudget.getValueFactory().setValue(100);

        if (spRequestTimeoutMs != null) spRequestTimeoutMs.getValueFactory().setValue(5000);
        if (spMaxResponseSizeBytes != null) spMaxResponseSizeBytes.getValueFactory().setValue(1048576);
        if (spRateLimitRps != null) spRateLimitRps.getValueFactory().setValue(10);
        if (spConcurrency != null) spConcurrency.getValueFactory().setValue(2);
        if (chkAllowUnsafeMethods != null) chkAllowUnsafeMethods.setSelected(false);
    }

    public boolean validateConfiguration() {
        if (cbProjects == null || cbProjects.getValue() == null) {
            showError("Please select an API Project to test.");
            return false;
        }

        if (chkValidCases != null && !chkValidCases.isSelected()
                && chkInvalidCases != null && !chkInvalidCases.isSelected()
                && chkBoundaryCases != null && !chkBoundaryCases.isSelected()) {
            showError("At least one test generation category (Valid, Invalid, Boundary) must be enabled.");
            return false;
        }

        if (spRateLimitRps != null && spRateLimitRps.getValue() <= 0) {
            showError("Rate limit must be greater than 0 req/sec.");
            return false;
        }

        if (spRequestTimeoutMs != null && spRequestTimeoutMs.getValue() < 100) {
            showError("Request timeout must be at least 100ms.");
            return false;
        }

        showError("");
        return true;
    }

    private void showError(String msg) {
        if (lblValidationMsg != null) {
            lblValidationMsg.setText(msg);
            lblValidationMsg.setVisible(msg != null && !msg.isBlank());
        }
    }

    @FXML
    private void onLaunchScan() {
        if (!validateConfiguration()) {
            return;
        }

        ApiProject project = cbProjects.getValue();
        if (ShellController.getInstance() != null) {
            ShellController.getInstance().openApiScanFor(project.getId());
        }
    }

    public ApiProject getSelectedProject() {
        return cbProjects != null ? cbProjects.getValue() : null;
    }

    public SearchConfiguration buildSearchConfiguration() {
        int pop = spPopulationSize != null ? spPopulationSize.getValue() : 20;
        int gen = spMaxGenerations != null ? spMaxGenerations.getValue() : 30;
        int budget = spEvaluationBudget != null ? spEvaluationBudget.getValue() : 100;
        double mutProb = spMutationProbability != null ? spMutationProbability.getValue() : 0.35;

        SearchConfiguration config = new SearchConfiguration();
        config.setPopulationSize(pop);
        config.setMaxGenerations(gen);
        config.setEvaluationBudget(budget);
        config.setMutationProbability(mutProb);
        config.setSeed(42L);
        return config;
    }

    public ApiExecutionConfiguration buildExecutionConfig() {
        int timeout = spRequestTimeoutMs != null ? spRequestTimeoutMs.getValue() : 5000;
        long maxBytes = spMaxResponseSizeBytes != null ? (long) spMaxResponseSizeBytes.getValue() : 1048576L;
        int rps = spRateLimitRps != null ? spRateLimitRps.getValue() : 10;
        int concurrency = spConcurrency != null ? spConcurrency.getValue() : 2;
        boolean allowUnsafe = chkAllowUnsafeMethods != null && chkAllowUnsafeMethods.isSelected();

        ApiExecutionConfiguration config = new ApiExecutionConfiguration();
        config.setRequestTimeout(Duration.ofMillis(timeout));
        config.setMaxResponseSizeBytes(maxBytes);
        config.setRequestsPerSecond(rps);
        config.setMaxConcurrentRequests(concurrency);
        config.setAllowUnsafeMethods(allowUnsafe);
        return config;
    }
}
