package com.webshield.ui.controllers;

import com.webshield.api.dto.ApiFindingDto;
import com.webshield.api.dto.ApiScanDto;
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
 * Controller for inspecting API security vulnerabilities, OWASP API Top 10 mappings, evidence, and remediation.
 */
@Component
@Scope("prototype")
public class ApiSecurityFindingsController {

    private static final Logger log = LoggerFactory.getLogger(ApiSecurityFindingsController.class);

    @FXML private ComboBox<ApiScanDto> cbScans;
    @FXML private TextField tfSearch;
    @FXML private ComboBox<String> cbSeverityFilter;
    @FXML private ComboBox<String> cbConfidenceFilter;

    // Severity metric card labels (clickable)
    @FXML private Label lblTotalCount;
    @FXML private Label lblCriticalCount;
    @FXML private Label lblHighCount;
    @FXML private Label lblMediumCount;
    @FXML private Label lblLowCount;
    @FXML private Label lblInfoCount;

    @FXML private TableView<ApiFindingDto> tableFindings;
    @FXML private TableColumn<ApiFindingDto, String> colSeverity;
    @FXML private TableColumn<ApiFindingDto, String> colTitle;
    @FXML private TableColumn<ApiFindingDto, String> colEndpoint;
    @FXML private TableColumn<ApiFindingDto, String> colMethod;
    @FXML private TableColumn<ApiFindingDto, String> colConfidence;
    @FXML private TableColumn<ApiFindingDto, String> colOwasp;
    @FXML private TableColumn<ApiFindingDto, String> colCwe;

    // Detail inspector
    @FXML private VBox paneFindingDetails;
    @FXML private Label lblDetailTitle;
    @FXML private Label lblDetailSeverity;
    @FXML private Label lblDetailConfidence;
    @FXML private Label lblDetailOwasp;
    @FXML private Label lblDetailCwe;
    @FXML private Label lblDetailEndpoint;
    @FXML private TextArea txtEvidence;
    @FXML private TextArea txtRemediation;

    // AI Explanation section
    @FXML private Button btnExplainWithAi;
    @FXML private ProgressIndicator piAiLoading;
    @FXML private VBox paneAiExplanation;
    @FXML private Label lblAiProvider;
    @FXML private TextArea txtAiExplanation;
    @FXML private Label lblAiDisclaimer;

    private final ApiPersistenceService persistenceService;
    private final com.webshield.api.llm.LlmService llmService;
    private final ObservableList<ApiFindingDto> masterList = FXCollections.observableArrayList();
    private FilteredList<ApiFindingDto> filteredList;
    private Long preselectedScanId;

    public ApiSecurityFindingsController() {
        this(SpringContext.getBean(ApiPersistenceService.class), SpringContext.getBean(com.webshield.api.llm.LlmService.class));
    }

    public ApiSecurityFindingsController(ApiPersistenceService persistenceService) {
        this(persistenceService, SpringContext.getBean(com.webshield.api.llm.LlmService.class));
    }

    public ApiSecurityFindingsController(ApiPersistenceService persistenceService, com.webshield.api.llm.LlmService llmService) {
        this.persistenceService = persistenceService;
        this.llmService = llmService != null ? llmService : new com.webshield.api.llm.LlmService();
    }

    @FXML
    public void initialize() {
        configureTables();
        configureFilters();
        loadScansAsync();
    }

    private void configureTables() {
        if (colSeverity != null) colSeverity.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().severity()));
        if (colTitle != null) colTitle.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().title()));
        if (colEndpoint != null) colEndpoint.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().endpointPath()));
        if (colMethod != null) colMethod.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().httpMethod()));
        if (colConfidence != null) colConfidence.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().confidence()));
        if (colOwasp != null) colOwasp.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().owaspCategory() != null ? d.getValue().owaspCategory() : "—"));
        if (colCwe != null) colCwe.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().cweId() != null ? d.getValue().cweId() : "—"));

        if (tableFindings != null) {
            tableFindings.getSelectionModel().selectedItemProperty().addListener((obs, oldV, selected) -> displayDetails(selected));
        }
    }

    private void configureFilters() {
        filteredList = new FilteredList<>(masterList, f -> true);

        if (cbSeverityFilter != null) {
            cbSeverityFilter.setItems(FXCollections.observableArrayList("ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"));
            cbSeverityFilter.setValue("ALL");
            cbSeverityFilter.valueProperty().addListener((obs, oldV, newV) -> applyFilters());
        }

        if (cbConfidenceFilter != null) {
            cbConfidenceFilter.setItems(FXCollections.observableArrayList("ALL", "HIGH", "MEDIUM", "LOW"));
            cbConfidenceFilter.setValue("ALL");
            cbConfidenceFilter.valueProperty().addListener((obs, oldV, newV) -> applyFilters());
        }

        if (tfSearch != null) {
            tfSearch.textProperty().addListener((obs, oldV, newV) -> applyFilters());
        }

        if (tableFindings != null) {
            tableFindings.setItems(filteredList);
        }

        if (cbScans != null) {
            cbScans.setConverter(new StringConverter<>() {
                @Override
                public String toString(ApiScanDto scan) {
                    return scan != null ? "#" + scan.id() + " - " + scan.scanName() + " (" + scan.totalFindings() + " findings)" : "";
                }

                @Override
                public ApiScanDto fromString(String string) {
                    return null;
                }
            });

            cbScans.valueProperty().addListener((obs, oldV, selected) -> {
                if (selected != null) {
                    loadFindingsForScan(selected.id());
                }
            });
        }
    }

    private void applyFilters() {
        String sev = cbSeverityFilter != null ? cbSeverityFilter.getValue() : "ALL";
        String conf = cbConfidenceFilter != null ? cbConfidenceFilter.getValue() : "ALL";
        String search = tfSearch != null ? tfSearch.getText() : null;
        String query = search != null ? search.trim().toLowerCase() : "";

        filteredList.setPredicate(f -> {
            boolean sevMatches = "ALL".equalsIgnoreCase(sev) || (f.severity() != null && f.severity().equalsIgnoreCase(sev));
            if (!sevMatches) return false;

            boolean confMatches = "ALL".equalsIgnoreCase(conf) || (f.confidence() != null && f.confidence().equalsIgnoreCase(conf));
            if (!confMatches) return false;

            if (query.isEmpty()) return true;
            boolean titleMatches = f.title() != null && f.title().toLowerCase().contains(query);
            boolean epMatches = f.endpointPath() != null && f.endpointPath().toLowerCase().contains(query);
            boolean ruleMatches = f.ruleId() != null && f.ruleId().toLowerCase().contains(query);
            boolean cweMatches = f.cweId() != null && f.cweId().toLowerCase().contains(query);
            boolean owaspMatches = f.owaspCategory() != null && f.owaspCategory().toLowerCase().contains(query);
            return titleMatches || epMatches || ruleMatches || cweMatches || owaspMatches;
        });
    }

    private void updateSeverityCounts() {
        long total = masterList.size();
        long crit = masterList.stream().filter(f -> "CRITICAL".equalsIgnoreCase(f.severity())).count();
        long high = masterList.stream().filter(f -> "HIGH".equalsIgnoreCase(f.severity())).count();
        long med = masterList.stream().filter(f -> "MEDIUM".equalsIgnoreCase(f.severity())).count();
        long low = masterList.stream().filter(f -> "LOW".equalsIgnoreCase(f.severity())).count();
        long info = masterList.stream().filter(f -> "INFORMATIONAL".equalsIgnoreCase(f.severity())).count();

        if (lblTotalCount != null) lblTotalCount.setText(String.valueOf(total));
        if (lblCriticalCount != null) lblCriticalCount.setText(String.valueOf(crit));
        if (lblHighCount != null) lblHighCount.setText(String.valueOf(high));
        if (lblMediumCount != null) lblMediumCount.setText(String.valueOf(med));
        if (lblLowCount != null) lblLowCount.setText(String.valueOf(low));
        if (lblInfoCount != null) lblInfoCount.setText(String.valueOf(info));
    }

    @FXML public void onFilterAll() { setSeverityFilter("ALL"); }
    @FXML public void onFilterCritical() { setSeverityFilter("CRITICAL"); }
    @FXML public void onFilterHigh() { setSeverityFilter("HIGH"); }
    @FXML public void onFilterMedium() { setSeverityFilter("MEDIUM"); }
    @FXML public void onFilterLow() { setSeverityFilter("LOW"); }
    @FXML public void onFilterInfo() { setSeverityFilter("INFORMATIONAL"); }

    private void setSeverityFilter(String severity) {
        if (cbSeverityFilter != null) {
            cbSeverityFilter.setValue(severity);
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
        Thread thread = new Thread(task, "load-findings-scans");
        thread.setDaemon(true);
        thread.start();
    }

    public void loadFindingsForScan(Long scanId) {
        if (scanId == null || persistenceService == null) return;
        User user = SessionManager.getInstance().getCurrentUser();
        Long userId = user != null ? user.getId() : 1L;

        Task<List<ApiFindingDto>> task = new Task<>() {
            @Override
            protected List<ApiFindingDto> call() {
                return persistenceService.getFindingsForScan(scanId, userId);
            }

            @Override
            protected void succeeded() {
                masterList.setAll(getValue());
                updateSeverityCounts();
                applyFilters();
                if (!masterList.isEmpty() && tableFindings != null) {
                    tableFindings.getSelectionModel().select(0);
                }
            }
        };
        Thread thread = new Thread(task, "load-findings");
        thread.setDaemon(true);
        thread.start();
    }

    private void displayDetails(ApiFindingDto f) {
        if (f == null) {
            if (paneFindingDetails != null) paneFindingDetails.setVisible(false);
            return;
        }
        if (paneFindingDetails != null) paneFindingDetails.setVisible(true);

        if (lblDetailTitle != null) lblDetailTitle.setText(f.title());
        if (lblDetailSeverity != null) {
            lblDetailSeverity.setText(f.severity());
            lblDetailSeverity.getStyleClass().removeAll("ws-badge-critical", "ws-badge-high", "ws-badge-warning", "ws-badge-info", "ws-badge-neutral");
            if ("CRITICAL".equalsIgnoreCase(f.severity())) lblDetailSeverity.getStyleClass().add("ws-badge-critical");
            else if ("HIGH".equalsIgnoreCase(f.severity())) lblDetailSeverity.getStyleClass().add("ws-badge-high");
            else if ("MEDIUM".equalsIgnoreCase(f.severity())) lblDetailSeverity.getStyleClass().add("ws-badge-warning");
            else lblDetailSeverity.getStyleClass().add("ws-badge-info");
        }
        if (lblDetailConfidence != null) lblDetailConfidence.setText("Confidence: " + f.confidence());
        if (lblDetailOwasp != null) lblDetailOwasp.setText("OWASP: " + (f.owaspCategory() != null ? f.owaspCategory() : "—"));
        if (lblDetailCwe != null) lblDetailCwe.setText("CWE: " + (f.cweId() != null ? f.cweId() : "—"));
        if (lblDetailEndpoint != null) lblDetailEndpoint.setText((f.httpMethod() != null ? f.httpMethod() + " " : "") + f.endpointPath());

        if (txtEvidence != null) {
            txtEvidence.setText(f.evidence() != null && !f.evidence().isBlank()
                    ? f.evidence() : "(No evidence snippet recorded)");
        }
        if (txtRemediation != null) {
            txtRemediation.setText(f.remediation() != null && !f.remediation().isBlank()
                    ? f.remediation() : "Consult OWASP API Security guidelines for remediation advice.");
        }

        // Reset AI explanation panel on new finding selection
        if (paneAiExplanation != null) {
            paneAiExplanation.setVisible(false);
            paneAiExplanation.setManaged(false);
        }
        if (txtAiExplanation != null) {
            txtAiExplanation.clear();
        }
        if (btnExplainWithAi != null) {
            btnExplainWithAi.setDisable(false);
        }
    }

    @FXML
    public void onExplainWithAi() {
        ApiFindingDto selected = tableFindings != null ? tableFindings.getSelectionModel().getSelectedItem() : null;
        if (selected == null || llmService == null) return;

        if (paneAiExplanation != null) {
            paneAiExplanation.setVisible(true);
            paneAiExplanation.setManaged(true);
        }
        if (piAiLoading != null) {
            piAiLoading.setVisible(true);
            piAiLoading.setManaged(true);
        }
        if (btnExplainWithAi != null) btnExplainWithAi.setDisable(true);
        if (txtAiExplanation != null) txtAiExplanation.setText("Generating technical finding explanation with AI assistant...");

        Task<com.webshield.api.llm.LlmFindingExplanation> task = new Task<>() {
            @Override
            protected com.webshield.api.llm.LlmFindingExplanation call() {
                return llmService.explainFinding(selected, true);
            }

            @Override
            protected void succeeded() {
                if (btnExplainWithAi != null) btnExplainWithAi.setDisable(false);
                if (piAiLoading != null) {
                    piAiLoading.setVisible(false);
                    piAiLoading.setManaged(false);
                }
                com.webshield.api.llm.LlmFindingExplanation expl = getValue();
                if (expl != null) {
                    if (lblAiProvider != null) lblAiProvider.setText("Provider: " + expl.providerName());
                    if (txtAiExplanation != null) {
                        String body = "SUMMARY:\n" + expl.summary() + "\n\n" +
                                "POTENTIAL IMPACT:\n" + expl.potentialImpact() + "\n\n" +
                                "EXPLOITATION WALKTHROUGH:\n" + expl.exploitationScenario() + "\n\n" +
                                "RECOMMENDED HARDENING:\n" + expl.remediationGuide();
                        txtAiExplanation.setText(body);
                    }
                    if (lblAiDisclaimer != null) lblAiDisclaimer.setText(expl.disclaimer());
                }
            }

            @Override
            protected void failed() {
                if (btnExplainWithAi != null) btnExplainWithAi.setDisable(false);
                if (piAiLoading != null) {
                    piAiLoading.setVisible(false);
                    piAiLoading.setManaged(false);
                }
                if (txtAiExplanation != null) {
                    txtAiExplanation.setText("AI explanation service unavailable. Please refer to deterministic OWASP remediation guidance.");
                }
            }
        };

        Thread thread = new Thread(task, "ai-explain-finding");
        thread.setDaemon(true);
        thread.start();
    }
}

