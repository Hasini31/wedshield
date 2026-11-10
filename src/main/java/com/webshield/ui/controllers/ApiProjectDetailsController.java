package com.webshield.ui.controllers;

import com.webshield.api.models.*;
import com.webshield.api.parser.OpenApiParser;
import com.webshield.api.service.ApiProjectService;
import com.webshield.config.SpringContext;
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

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Controller for inspecting detailed OpenAPI specifications, servers, and endpoints.
 */
@Component
@Scope("prototype")
public class ApiProjectDetailsController {

    private static final Logger log = LoggerFactory.getLogger(ApiProjectDetailsController.class);

    @FXML private Label lblProjectName;
    @FXML private Label lblSpecVersion;
    @FXML private Label lblBaseUrl;
    @FXML private Label lblEndpointCount;
    @FXML private Label lblProjectDescription;

    @FXML private Label lblCountGet;
    @FXML private Label lblCountPost;
    @FXML private Label lblCountPut;
    @FXML private Label lblCountDelete;
    @FXML private Label lblCountOther;

    @FXML private TextField tfEndpointSearch;
    @FXML private ComboBox<String> cbMethodFilter;

    @FXML private TableView<ApiEndpoint> tableEndpoints;
    @FXML private TableColumn<ApiEndpoint, String> colMethod;
    @FXML private TableColumn<ApiEndpoint, String> colPath;
    @FXML private TableColumn<ApiEndpoint, String> colSummary;
    @FXML private TableColumn<ApiEndpoint, String> colParamCount;

    // Selected endpoint detail controls
    @FXML private VBox paneEndpointDetails;
    @FXML private Label lblDetailMethod;
    @FXML private Label lblDetailPath;
    @FXML private Label lblDetailSummary;
    @FXML private Label lblDetailDescription;

    @FXML private TableView<ApiParameter> tableParams;
    @FXML private TableColumn<ApiParameter, String> colParamName;
    @FXML private TableColumn<ApiParameter, String> colParamIn;
    @FXML private TableColumn<ApiParameter, String> colParamType;
    @FXML private TableColumn<ApiParameter, String> colParamRequired;
    @FXML private TableColumn<ApiParameter, String> colParamDesc;

    @FXML private TextArea txtRequestBodySchema;
    @FXML private TextArea txtResponseSchemas;
    @FXML private Label lblSecurityReqs;

    private final ApiProjectService apiProjectService;
    private final OpenApiParser openApiParser;

    private ApiProject currentProject;
    private ParsedApiSpecification parsedSpec;
    private final ObservableList<ApiEndpoint> endpointMasterList = FXCollections.observableArrayList();
    private FilteredList<ApiEndpoint> endpointFilteredList;

    public ApiProjectDetailsController() {
        this(SpringContext.getBean(ApiProjectService.class), new OpenApiParser());
    }

    public ApiProjectDetailsController(ApiProjectService apiProjectService, OpenApiParser openApiParser) {
        this.apiProjectService = apiProjectService != null ? apiProjectService : new ApiProjectService();
        this.openApiParser = openApiParser != null ? openApiParser : new OpenApiParser();
    }

    @FXML
    public void initialize() {
        configureTables();
        configureFilters();
    }

    private void configureTables() {
        if (colMethod != null) {
            colMethod.setCellValueFactory(d -> new SimpleStringProperty(
                    d.getValue().getMethod() != null ? d.getValue().getMethod().name() : "GET"));
        }
        if (colPath != null) {
            colPath.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getPath()));
        }
        if (colSummary != null) {
            colSummary.setCellValueFactory(d -> new SimpleStringProperty(
                    d.getValue().getSummary() != null && !d.getValue().getSummary().isBlank()
                            ? d.getValue().getSummary() : "—"));
        }
        if (colParamCount != null) {
            colParamCount.setCellValueFactory(d -> new SimpleStringProperty(
                    String.valueOf(d.getValue().getParameters() != null ? d.getValue().getParameters().size() : 0)));
        }

        if (tableEndpoints != null) {
            tableEndpoints.getSelectionModel().selectedItemProperty().addListener((obs, oldV, selected) -> {
                displayEndpointDetails(selected);
            });
        }

        if (tableParams != null) {
            if (colParamName != null) colParamName.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getName()));
            if (colParamIn != null) colParamIn.setCellValueFactory(d -> new SimpleStringProperty(
                    d.getValue().getLocation() != null ? d.getValue().getLocation().name() : "QUERY"));
            if (colParamType != null) colParamType.setCellValueFactory(d -> new SimpleStringProperty(
                    d.getValue().getSchema() != null && d.getValue().getSchema().getType() != null ? d.getValue().getSchema().getType().name() : "STRING"));
            if (colParamRequired != null) colParamRequired.setCellValueFactory(d -> new SimpleStringProperty(
                    d.getValue().isRequired() ? "Yes" : "No"));
            if (colParamDesc != null) colParamDesc.setCellValueFactory(d -> new SimpleStringProperty(
                    d.getValue().getDescription() != null ? d.getValue().getDescription() : "—"));
        }
    }

    private void configureFilters() {
        endpointFilteredList = new FilteredList<>(endpointMasterList, ep -> true);
        if (cbMethodFilter != null) {
            cbMethodFilter.setItems(FXCollections.observableArrayList("ALL", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"));
            cbMethodFilter.setValue("ALL");
            cbMethodFilter.valueProperty().addListener((obs, oldV, newV) -> applyFilters());
        }

        if (tfEndpointSearch != null) {
            tfEndpointSearch.textProperty().addListener((obs, oldV, newV) -> applyFilters());
        }

        if (tableEndpoints != null) {
            tableEndpoints.setItems(endpointFilteredList);
        }
    }

    private void applyFilters() {
        String methodFilter = cbMethodFilter != null ? cbMethodFilter.getValue() : "ALL";
        String search = tfEndpointSearch != null ? tfEndpointSearch.getText() : null;
        String query = search != null ? search.trim().toLowerCase() : "";

        endpointFilteredList.setPredicate(ep -> {
            boolean methodMatches = "ALL".equalsIgnoreCase(methodFilter)
                    || (ep.getMethod() != null && ep.getMethod().name().equalsIgnoreCase(methodFilter));
            if (!methodMatches) return false;

            if (query.isEmpty()) return true;
            boolean pathMatches = ep.getPath() != null && ep.getPath().toLowerCase().contains(query);
            boolean summaryMatches = ep.getSummary() != null && ep.getSummary().toLowerCase().contains(query);
            boolean descMatches = ep.getDescription() != null && ep.getDescription().toLowerCase().contains(query);
            return pathMatches || summaryMatches || descMatches;
        });
    }

    public void loadProject(Long projectId) {
        if (projectId == null) return;
        Task<ApiProject> task = new Task<>() {
            @Override
            protected ApiProject call() {
                return apiProjectService.getProjectsForCurrentUser().stream()
                        .filter(p -> p.getId().equals(projectId))
                        .findFirst()
                        .orElse(null);
            }

            @Override
            protected void succeeded() {
                ApiProject p = getValue();
                if (p != null) {
                    populateProject(p);
                } else {
                    log.warn("Project id {} not found for current user", projectId);
                }
            }

            @Override
            protected void failed() {
                log.error("Failed to load project details for id={}", projectId, getException());
            }
        };
        Thread thread = new Thread(task, "load-project-details");
        thread.setDaemon(true);
        thread.start();
    }

    public void populateProject(ApiProject project) {
        this.currentProject = project;
        if (lblProjectName != null) lblProjectName.setText(project.getName());
        if (lblProjectDescription != null) {
            lblProjectDescription.setText(project.getDescription() != null && !project.getDescription().isBlank()
                    ? project.getDescription() : "No description provided.");
        }

        if (project.getRawSpecification() != null && !project.getRawSpecification().isBlank()) {
            try {
                parsedSpec = openApiParser.parse(project.getRawSpecification());
                renderParsedSpec(parsedSpec);
            } catch (Exception e) {
                log.error("Failed to parse OpenAPI spec for project {}", project.getName(), e);
            }
        }
    }

    private void renderParsedSpec(ParsedApiSpecification spec) {
        if (spec == null) {
            if (lblEndpointCount != null) lblEndpointCount.setText("0");
            return;
        }

        if (lblSpecVersion != null) {
            String ver = (spec.getMetadata() != null && spec.getMetadata().getVersion() != null)
                    ? spec.getMetadata().getVersion()
                    : "OpenAPI";
            lblSpecVersion.setText(ver);
        }

        if (lblBaseUrl != null) {
            String server = (spec.getMetadata() != null && spec.getMetadata().getServers() != null && !spec.getMetadata().getServers().isEmpty())
                    ? spec.getMetadata().getServers().get(0)
                    : "http://localhost";
            lblBaseUrl.setText(server);
        }

        List<ApiEndpoint> endpoints = spec.getEndpoints() != null ? spec.getEndpoints() : List.of();
        if (lblEndpointCount != null) {
            lblEndpointCount.setText(String.valueOf(endpoints.size()));
        }

        Map<String, Long> methodCounts = endpoints.stream()
                .collect(Collectors.groupingBy(e -> e.getMethod() != null ? e.getMethod().name() : "GET", Collectors.counting()));

        if (lblCountGet != null) lblCountGet.setText(String.valueOf(methodCounts.getOrDefault("GET", 0L)));
        if (lblCountPost != null) lblCountPost.setText(String.valueOf(methodCounts.getOrDefault("POST", 0L)));
        if (lblCountPut != null) lblCountPut.setText(String.valueOf(methodCounts.getOrDefault("PUT", 0L)));
        if (lblCountDelete != null) lblCountDelete.setText(String.valueOf(methodCounts.getOrDefault("DELETE", 0L)));
        long otherCount = endpoints.size()
                - methodCounts.getOrDefault("GET", 0L)
                - methodCounts.getOrDefault("POST", 0L)
                - methodCounts.getOrDefault("PUT", 0L)
                - methodCounts.getOrDefault("DELETE", 0L);
        if (lblCountOther != null) lblCountOther.setText(String.valueOf(Math.max(0, otherCount)));

        endpointMasterList.setAll(endpoints);
        applyFilters();

        if (!endpoints.isEmpty() && tableEndpoints != null) {
            tableEndpoints.getSelectionModel().select(0);
        }
    }

    private void displayEndpointDetails(ApiEndpoint ep) {
        if (ep == null) {
            if (paneEndpointDetails != null) paneEndpointDetails.setVisible(false);
            return;
        }
        if (paneEndpointDetails != null) paneEndpointDetails.setVisible(true);

        if (lblDetailMethod != null) lblDetailMethod.setText(ep.getMethod() != null ? ep.getMethod().name() : "GET");
        if (lblDetailPath != null) lblDetailPath.setText(ep.getPath());
        if (lblDetailSummary != null) lblDetailSummary.setText(ep.getSummary() != null ? ep.getSummary() : "No summary");
        if (lblDetailDescription != null) {
            lblDetailDescription.setText(ep.getDescription() != null && !ep.getDescription().isBlank() ? ep.getDescription() : "—");
        }

        if (tableParams != null) {
            tableParams.setItems(FXCollections.observableArrayList(ep.getParameters() != null ? ep.getParameters() : List.of()));
        }

        if (txtRequestBodySchema != null) {
            if (ep.getRequestBody() != null && ep.getRequestBody().getJsonSchema() != null) {
                txtRequestBodySchema.setText(ep.getRequestBody().getJsonSchema().toString());
            } else {
                txtRequestBodySchema.setText("No request body defined for this endpoint.");
            }
        }

        if (txtResponseSchemas != null) {
            if (ep.getResponses() != null && !ep.getResponses().isEmpty()) {
                StringBuilder sb = new StringBuilder();
                ep.getResponses().forEach((code, resp) -> {
                    sb.append("HTTP ").append(code).append(": ")
                            .append(resp.getDescription() != null ? resp.getDescription() : "")
                            .append("\n");
                    if (resp.getJsonSchema() != null) {
                        sb.append("Schema: ").append(resp.getJsonSchema().toString()).append("\n");
                    }
                    sb.append("\n");
                });
                txtResponseSchemas.setText(sb.toString().trim());
            } else {
                txtResponseSchemas.setText("No response definitions declared.");
            }
        }

        if (lblSecurityReqs != null) {
            if (ep.getSecurityRequirements() != null && !ep.getSecurityRequirements().isEmpty()) {
                String reqs = ep.getSecurityRequirements().stream()
                        .map(ApiSecurityRequirement::getSchemeName)
                        .collect(Collectors.joining(", "));
                lblSecurityReqs.setText(reqs);
            } else {
                lblSecurityReqs.setText("None (Public Endpoint)");
            }
        }
    }

    @FXML
    private void onBackToProjects() {
        if (ShellController.getInstance() != null) {
            ShellController.getInstance().openApiProjects();
        }
    }

    @FXML
    private void onConfigureScan() {
        if (currentProject != null && ShellController.getInstance() != null) {
            ShellController.getInstance().openApiTestConfigFor(currentProject.getId());
        }
    }

    @FXML
    private void onQuickScan() {
        if (currentProject != null && ShellController.getInstance() != null) {
            ShellController.getInstance().openApiScanFor(currentProject.getId());
        }
    }

    public ApiProject getCurrentProject() {
        return currentProject;
    }

    public ParsedApiSpecification getParsedSpec() {
        return parsedSpec;
    }
}
