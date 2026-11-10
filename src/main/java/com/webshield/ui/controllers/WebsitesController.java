package com.webshield.ui.controllers;

import com.webshield.models.Website;
import com.webshield.website.WebsiteService;
import javafx.application.Platform;
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

import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

/**
 * Controller for the Websites page: lists, searches, adds, edits, deletes,
 * and opens details for registered authorized targets.
 */
@Component
@Scope("prototype")
public class WebsitesController {

    private static final Logger log = LoggerFactory.getLogger(WebsitesController.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm");

    @FXML private TextField tfSearch;
    @FXML private Button btnAddWebsite;
    @FXML private Button btnEdit;
    @FXML private Button btnDelete;
    @FXML private Button btnDetails;

    @FXML private TableView<Website> tableWebsites;
    @FXML private TableColumn<Website, String> colName;
    @FXML private TableColumn<Website, String> colUrl;
    @FXML private TableColumn<Website, String> colDesc;
    @FXML private TableColumn<Website, String> colStatus;
    @FXML private TableColumn<Website, String> colLastScan;
    @FXML private TableColumn<Website, String> colFindings;
    @FXML private TableColumn<Website, String> colAdded;

    @FXML private Label lblWebsiteCount;
    @FXML private Label lblWebsiteCountText;

    private final WebsiteService websiteService;
    private final ObservableList<Website> masterList = FXCollections.observableArrayList();
    private FilteredList<Website> filteredList;

    public WebsitesController() {
        this(com.webshield.config.SpringContext.getBean(WebsiteService.class));
    }

    public WebsitesController(WebsiteService websiteService) {
        this.websiteService = websiteService != null ? websiteService : new WebsiteService();
    }

    @FXML
    public void initialize() {
        configureTable();
        setupSearchFilter();
        loadWebsitesAsync();
    }

    private void configureTable() {
        colName.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().getName()));
        colUrl.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().getUrl()));
        colDesc.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(
                d.getValue().getDescription() != null ? d.getValue().getDescription() : "—"));
        colStatus.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().getStatus()));
        colLastScan.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(
                d.getValue().getLastScanAt() != null ? d.getValue().getLastScanAt().format(FMT) : "Not scanned"));
        colFindings.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(
                String.valueOf(d.getValue().getFindingCount())));
        colAdded.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(
                d.getValue().getCreatedAt() != null ? d.getValue().getCreatedAt().format(FMT) : "—"));

        // Double click to view details
        tableWebsites.setRowFactory(tv -> {
            TableRow<Website> row = new TableRow<>();
            row.setOnMouseClicked(event -> {
                if (event.getClickCount() == 2 && (!row.isEmpty())) {
                    onViewDetails();
                }
            });
            return row;
        });

        // Disable buttons if nothing selected
        btnEdit.disableProperty().bind(tableWebsites.getSelectionModel().selectedItemProperty().isNull());
        btnDelete.disableProperty().bind(tableWebsites.getSelectionModel().selectedItemProperty().isNull());
        btnDetails.disableProperty().bind(tableWebsites.getSelectionModel().selectedItemProperty().isNull());
    }

    private void setupSearchFilter() {
        filteredList = new FilteredList<>(masterList, p -> true);
        tfSearch.textProperty().addListener((observable, oldValue, newValue) -> {
            filteredList.setPredicate(website -> {
                if (newValue == null || newValue.isBlank()) return true;
                String lower = newValue.toLowerCase().trim();
                return website.getName().toLowerCase().contains(lower) ||
                       website.getUrl().toLowerCase().contains(lower);
            });
            updateCountLabel();
        });
        tableWebsites.setItems(filteredList);
    }

    public void loadWebsitesAsync() {
        Task<List<Website>> task = new Task<>() {
            @Override
            protected List<Website> call() {
                return websiteService.getUserWebsites();
            }

            @Override
            protected void succeeded() {
                masterList.setAll(getValue());
                updateCountLabel();
            }

            @Override
            protected void failed() {
                log.error("Failed to load websites", getException());
            }
        };

        Thread t = new Thread(task, "load-websites");
        t.setDaemon(true);
        t.start();
    }

    private void updateCountLabel() {
        int count = filteredList.size();
        if (lblWebsiteCountText != null) {
            lblWebsiteCountText.setText(count + (count == 1 ? " website" : " websites"));
        }
    }

    @FXML
    private void onRefresh() {
        loadWebsitesAsync();
    }

    @FXML
    private void onAddWebsite() {
        openAddEditDialog(null);
    }

    @FXML
    private void onEditWebsite() {
        Website selected = tableWebsites.getSelectionModel().getSelectedItem();
        if (selected != null) {
            openAddEditDialog(selected);
        }
    }

    @FXML
    private void onDeleteWebsite() {
        Website selected = tableWebsites.getSelectionModel().getSelectedItem();
        if (selected == null) return;

        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
        confirm.setTitle("Confirm Deletion");
        confirm.setHeaderText("Delete Website Target");
        confirm.setContentText("Are you sure you want to delete '" + selected.getName() + "' (" + selected.getUrl() + ")?\nThis will also remove associated scans and findings.");

        confirm.showAndWait().ifPresent(res -> {
            if (res == ButtonType.OK) {
                try {
                    websiteService.deleteWebsite(selected.getId());
                    loadWebsitesAsync();
                } catch (Exception e) {
                    log.error("Failed to delete website", e);
                }
            }
        });
    }

    @FXML
    private void onViewDetails() {
        Website selected = tableWebsites.getSelectionModel().getSelectedItem();
        if (selected != null && ShellController.getInstance() != null) {
            ShellController.getInstance().openWebsiteDetails(selected.getId());
        }
    }

    private void openAddEditDialog(Website websiteToEdit) {
        try {
            FXMLLoader loader = com.webshield.config.SpringContext.createLoader(getClass().getResource("/fxml/pages/add_website_dialog.fxml"));
            Parent root = loader.load();
            AddWebsiteController controller = loader.getController();

            if (websiteToEdit != null) {
                controller.setEditingWebsite(websiteToEdit);
            }
            controller.setOnSaveCallback(this::loadWebsitesAsync);

            Stage dialogStage = new Stage();
            dialogStage.initModality(Modality.APPLICATION_MODAL);
            dialogStage.setTitle(websiteToEdit == null ? "Register Website Target" : "Edit Website Target");
            Scene scene = new Scene(root);
            dialogStage.setScene(scene);
            dialogStage.setResizable(false);
            dialogStage.showAndWait();
        } catch (IOException e) {
            log.error("Failed to open Add/Edit website dialog", e);
        }
    }
}
