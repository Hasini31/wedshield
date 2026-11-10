package com.webshield.ui.controllers;

import com.webshield.api.service.ApiProjectService;
import com.webshield.config.SpringContext;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import java.io.File;

/**
 * Controller for the OpenAPI/Swagger specification import dialog.
 */
@Component
@Scope("prototype")
public class ImportSpecDialogController {

    private static final Logger log = LoggerFactory.getLogger(ImportSpecDialogController.class);

    @FXML private Label lblDialogTitle;
    @FXML private TextField tfName;
    @FXML private TextArea taDescription;
    @FXML private RadioButton rbFile;
    @FXML private RadioButton rbUrl;
    @FXML private ToggleGroup sourceGroup;
    @FXML private VBox boxFile;
    @FXML private TextField tfFilePath;
    @FXML private Button btnBrowse;
    @FXML private VBox boxUrl;
    @FXML private TextField tfUrl;
    @FXML private Label lblError;
    @FXML private Button btnCancel;
    @FXML private Button btnImport;

    private final ApiProjectService apiProjectService;
    private File selectedFile;
    private Runnable onSuccessCallback;

    public ImportSpecDialogController() {
        this(SpringContext.getBean(ApiProjectService.class));
    }

    public ImportSpecDialogController(ApiProjectService apiProjectService) {
        this.apiProjectService = apiProjectService != null
                ? apiProjectService
                : new ApiProjectService();
    }

    @FXML
    public void initialize() {
        lblError.setText("");

        sourceGroup.selectedToggleProperty().addListener((obs, oldVal, newVal) -> {
            boolean isFile = rbFile.isSelected();
            boxFile.setVisible(isFile);
            boxFile.setManaged(isFile);
            boxUrl.setVisible(!isFile);
            boxUrl.setManaged(!isFile);
            lblError.setText("");
        });
    }

    public void setOnSuccessCallback(Runnable callback) {
        this.onSuccessCallback = callback;
    }

    @FXML
    private void onBrowseFile() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Select OpenAPI / Swagger Specification File");
        chooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("API Specifications (*.json, *.yaml, *.yml)", "*.json", "*.yaml", "*.yml"),
                new FileChooser.ExtensionFilter("JSON Files (*.json)", "*.json"),
                new FileChooser.ExtensionFilter("YAML Files (*.yaml, *.yml)", "*.yaml", "*.yml"),
                new FileChooser.ExtensionFilter("All Files (*.*)", "*.*")
        );

        Stage stage = (Stage) btnBrowse.getScene().getWindow();
        File file = chooser.showOpenDialog(stage);
        if (file != null) {
            this.selectedFile = file;
            tfFilePath.setText(file.getAbsolutePath());
            if (tfName.getText() == null || tfName.getText().isBlank()) {
                String baseName = file.getName();
                int dotIdx = baseName.lastIndexOf('.');
                if (dotIdx > 0) {
                    baseName = baseName.substring(0, dotIdx);
                }
                tfName.setText(baseName);
            }
            lblError.setText("");
        }
    }

    @FXML
    private void onCancel() {
        closeStage();
    }

    @FXML
    private void onImport() {
        lblError.setText("");
        String name = tfName.getText() != null ? tfName.getText().trim() : "";
        String desc = taDescription.getText() != null ? taDescription.getText().trim() : "";

        if (name.isEmpty()) {
            lblError.setText("Project name is required.");
            tfName.requestFocus();
            return;
        }

        boolean isFile = rbFile.isSelected();
        if (isFile && selectedFile == null) {
            lblError.setText("Please select a specification file to upload.");
            return;
        }

        String url = tfUrl.getText() != null ? tfUrl.getText().trim() : "";
        if (!isFile && url.isEmpty()) {
            lblError.setText("Please enter a specification URL.");
            tfUrl.requestFocus();
            return;
        }

        btnImport.setDisable(true);
        btnCancel.setDisable(true);
        lblError.setStyle("-fx-text-fill: #0284C7;");
        lblError.setText("Importing and validating specification...");

        Task<Void> importTask = new Task<>() {
            @Override
            protected Void call() {
                if (isFile) {
                    apiProjectService.importFromFile(name, desc, selectedFile);
                } else {
                    apiProjectService.importFromUrl(name, desc, url);
                }
                return null;
            }

            @Override
            protected void succeeded() {
                Platform.runLater(() -> {
                    if (onSuccessCallback != null) {
                        onSuccessCallback.run();
                    }
                    closeStage();
                });
            }

            @Override
            protected void failed() {
                Throwable ex = getException();
                log.error("Failed to import specification", ex);
                Platform.runLater(() -> {
                    lblError.setStyle("-fx-text-fill: #DC2626;");
                    lblError.setText(ex.getMessage() != null ? ex.getMessage() : "Failed to import specification.");
                    btnImport.setDisable(false);
                    btnCancel.setDisable(false);
                });
            }
        };

        Thread thread = new Thread(importTask, "import-spec-worker");
        thread.setDaemon(true);
        thread.start();
    }

    private void closeStage() {
        Stage stage = (Stage) btnCancel.getScene().getWindow();
        if (stage != null) {
            stage.close();
        }
    }
}

