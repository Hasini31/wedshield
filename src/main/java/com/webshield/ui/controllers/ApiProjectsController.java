package com.webshield.ui.controllers;

import com.webshield.api.models.ApiProject;
import com.webshield.api.service.ApiProjectService;
import com.webshield.config.SpringContext;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.Modality;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Controller for managing API security testing projects and imported specifications.
 */
@Component
@Scope("prototype")
public class ApiProjectsController {

    private static final Logger log = LoggerFactory.getLogger(ApiProjectsController.class);

    @FXML private TextField tfSearch;
    @FXML private Button btnViewDetails;
    @FXML private Button btnConfigureScan;
    @FXML private Button btnEdit;
    @FXML private Button btnDelete;
    @FXML private Button btnImportSpec;

    @FXML private Label lblProjectCount;
    @FXML private Label lblProjectCountText;

    @FXML private TableView<ApiProject> tableProjects;
    @FXML private TableColumn<ApiProject, String> colName;
    @FXML private TableColumn<ApiProject, String> colSpecType;
    @FXML private TableColumn<ApiProject, String> colFormat;
    @FXML private TableColumn<ApiProject, String> colSource;
    @FXML private TableColumn<ApiProject, String> colEndpoints;
    @FXML private TableColumn<ApiProject, String> colCreatedAt;

    private final ApiProjectService apiProjectService;
    private final ObservableList<ApiProject> masterList = FXCollections.observableArrayList();
    private FilteredList<ApiProject> filteredList;

    public ApiProjectsController() {
        this(SpringContext.getBean(ApiProjectService.class));
    }

    public ApiProjectsController(ApiProjectService apiProjectService) {
        this.apiProjectService = apiProjectService != null
                ? apiProjectService
                : new ApiProjectService();
    }

    @FXML
    public void initialize() {
        configureTable();
        setupSearchFilter();
        loadProjectsAsync();
    }

    private void configureTable() {
        colName.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getName()));
        colSpecType.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().getSpecType() != null ? d.getValue().getSpecType().getDisplayName() : "Unknown"
        ));
        colFormat.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().getSpecFormat() != null ? d.getValue().getSpecFormat().name() : "—"
        ));
        colSource.setCellValueFactory(d -> {
            ApiProject p = d.getValue();
            String src = p.getSourceType() != null ? p.getSourceType().getDisplayName() : "—";
            if (p.getSourceUrl() != null && !p.getSourceUrl().isBlank()) {
                src += " (" + p.getSourceUrl() + ")";
            }
            return new SimpleStringProperty(src);
        });
        colEndpoints.setCellValueFactory(d -> new SimpleStringProperty(
                String.valueOf(d.getValue().getEndpointsCount())
        ));
        colCreatedAt.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().getFormattedCreatedAt()
        ));

        // Disable buttons if nothing is selected
        if (btnViewDetails != null) btnViewDetails.disableProperty().bind(tableProjects.getSelectionModel().selectedItemProperty().isNull());
        if (btnConfigureScan != null) btnConfigureScan.disableProperty().bind(tableProjects.getSelectionModel().selectedItemProperty().isNull());
        btnEdit.disableProperty().bind(tableProjects.getSelectionModel().selectedItemProperty().isNull());
        btnDelete.disableProperty().bind(tableProjects.getSelectionModel().selectedItemProperty().isNull());

        // Double click handler
        tableProjects.setRowFactory(tv -> {
            TableRow<ApiProject> row = new TableRow<>();
            row.setOnMouseClicked(event -> {
                if (event.getClickCount() == 2 && !row.isEmpty()) {
                    showProjectDetails(row.getItem());
                }
            });
            return row;
        });
    }

    private void setupSearchFilter() {
        filteredList = new FilteredList<>(masterList, p -> true);
        tfSearch.textProperty().addListener((obs, oldVal, newVal) -> {
            filteredList.setPredicate(project -> {
                if (newVal == null || newVal.isBlank()) {
                    return true;
                }
                String lower = newVal.toLowerCase().trim();
                boolean nameMatch = project.getName() != null && project.getName().toLowerCase().contains(lower);
                boolean descMatch = project.getDescription() != null && project.getDescription().toLowerCase().contains(lower);
                boolean urlMatch = project.getSourceUrl() != null && project.getSourceUrl().toLowerCase().contains(lower);
                return nameMatch || descMatch || urlMatch;
            });
            updateCountLabel();
        });
        tableProjects.setItems(filteredList);
    }

    public void loadProjectsAsync() {
        Task<List<ApiProject>> task = new Task<>() {
            @Override
            protected List<ApiProject> call() {
                return apiProjectService.getProjectsForCurrentUser();
            }

            @Override
            protected void succeeded() {
                masterList.setAll(getValue());
                updateCountLabel();
            }

            @Override
            protected void failed() {
                log.error("Failed to load API projects", getException());
            }
        };

        Thread thread = new Thread(task, "load-api-projects");
        thread.setDaemon(true);
        thread.start();
    }

    private void updateCountLabel() {
        int count = filteredList != null ? filteredList.size() : masterList.size();
        if (lblProjectCountText != null) {
            lblProjectCountText.setText(count + (count == 1 ? " project" : " projects"));
        }
    }

    @FXML
    private void onRefresh() {
        loadProjectsAsync();
    }

    @FXML
    private void onImportSpec() {
        try {
            FXMLLoader loader = SpringContext.createLoader(getClass().getResource("/fxml/pages/import_spec_dialog.fxml"));
            Parent root = loader.load();
            ImportSpecDialogController controller = loader.getController();
            controller.setOnSuccessCallback(this::loadProjectsAsync);

            Stage dialogStage = new Stage();
            dialogStage.initModality(Modality.APPLICATION_MODAL);
            dialogStage.setTitle("Import OpenAPI Specification");
            Scene scene = new Scene(root);
            dialogStage.setScene(scene);
            dialogStage.setResizable(false);
            dialogStage.showAndWait();
        } catch (IOException e) {
            log.error("Failed to open Import Specification dialog", e);
        }
    }

    @FXML
    private void onEditProject() {
        ApiProject selected = tableProjects.getSelectionModel().getSelectedItem();
        if (selected == null) {
            return;
        }

        TextInputDialog dialog = new TextInputDialog(selected.getName());
        dialog.setTitle("Edit Project Name");
        dialog.setHeaderText("Rename Project '" + selected.getName() + "'");
        dialog.setContentText("New project name:");

        Optional<String> result = dialog.showAndWait();
        result.ifPresent(newName -> {
            if (!newName.trim().isEmpty()) {
                try {
                    apiProjectService.updateProject(selected.getId(), newName.trim(), selected.getDescription());
                    loadProjectsAsync();
                } catch (Exception e) {
                    Alert alert = new Alert(Alert.AlertType.ERROR);
                    alert.setTitle("Error");
                    alert.setHeaderText("Failed to update project");
                    alert.setContentText(e.getMessage());
                    alert.showAndWait();
                }
            }
        });
    }

    @FXML
    private void onDeleteProject() {
        ApiProject selected = tableProjects.getSelectionModel().getSelectedItem();
        if (selected == null) {
            return;
        }

        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
        confirm.setTitle("Confirm Deletion");
        confirm.setHeaderText("Delete API Project");
        confirm.setContentText("Are you sure you want to delete '" + selected.getName() + "'?\nThis will remove the imported specification and all associated test cases.");

        confirm.showAndWait().ifPresent(res -> {
            if (res == ButtonType.OK) {
                try {
                    apiProjectService.deleteProject(selected.getId());
                    loadProjectsAsync();
                } catch (Exception e) {
                    log.error("Failed to delete project", e);
                }
            }
        });
    }

    @FXML
    private void onViewProjectDetails() {
        ApiProject selected = tableProjects.getSelectionModel().getSelectedItem();
        if (selected != null) {
            showProjectDetails(selected);
        }
    }

    @FXML
    private void onConfigureProjectScan() {
        ApiProject selected = tableProjects.getSelectionModel().getSelectedItem();
        if (selected != null && ShellController.getInstance() != null) {
            ShellController.getInstance().openApiTestConfigFor(selected.getId());
        }
    }

    private void showProjectDetails(ApiProject project) {
        if (project == null) return;
        if (ShellController.getInstance() != null) {
            ShellController.getInstance().openApiProjectDetails(project.getId());
            return;
        }
        Alert info = new Alert(Alert.AlertType.INFORMATION);
        info.setTitle("API Project Details");
        info.setHeaderText(project.getName());
        info.setContentText(String.format(
                "Specification Standard: %s\nFormat: %s\nEndpoints Detected: %d\nSource: %s\nCreated: %s\nDescription: %s",
                project.getSpecType().getDisplayName(),
                project.getSpecFormat(),
                project.getEndpointsCount(),
                project.getSourceType().getDisplayName() + (project.getSourceUrl() != null ? " (" + project.getSourceUrl() + ")" : ""),
                project.getFormattedCreatedAt(),
                project.getDescription() != null ? project.getDescription() : "None"
        ));
        info.showAndWait();
    }
}

