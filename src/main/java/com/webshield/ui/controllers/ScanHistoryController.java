package com.webshield.ui.controllers;

import com.webshield.auth.SessionManager;
import com.webshield.database.repositories.ScanRecord;
import com.webshield.models.User;
import com.webshield.scan.ScanService;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

/**
 * Controller for the Scan History page.
 */
@Component
@Scope("prototype")
public class ScanHistoryController {

    private static final Logger log = LoggerFactory.getLogger(ScanHistoryController.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm");

    @FXML private TextField tfSearch;
    @FXML private ComboBox<String> cbWebsiteFilter;
    @FXML private ComboBox<String> cbStatusFilter;

    @FXML private TableView<ScanRecord> tableScanHistory;
    @FXML private TableColumn<ScanRecord, String> colScanId;
    @FXML private TableColumn<ScanRecord, String> colTarget;
    @FXML private TableColumn<ScanRecord, String> colStarted;
    @FXML private TableColumn<ScanRecord, String> colDuration;
    @FXML private TableColumn<ScanRecord, String> colStatus;
    @FXML private TableColumn<ScanRecord, String> colFindings;
    @FXML private TableColumn<ScanRecord, String> colCritical;
    @FXML private TableColumn<ScanRecord, Void> colActions;

    private final ScanService scanService;
    private final ObservableList<ScanRecord> masterList = FXCollections.observableArrayList();
    private FilteredList<ScanRecord> filteredList;

    public ScanHistoryController() {
        this(com.webshield.config.SpringContext.getBean(ScanService.class));
    }

    public ScanHistoryController(ScanService scanService) {
        this.scanService = scanService != null ? scanService : new ScanService();
    }

    @FXML
    public void initialize() {
        configureTable();
        configureFilters();
        loadHistory();
    }

    private void configureTable() {
        colScanId.setCellValueFactory(d -> new SimpleStringProperty(String.valueOf(d.getValue().getId())));
        colTarget.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getWebsiteName()));
        colStarted.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().getStartedAt() != null ? d.getValue().getStartedAt().format(FMT) : "—"));
        colDuration.setCellValueFactory(d -> new SimpleStringProperty(formatDuration(d.getValue())));
        colStatus.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getStatus()));
        colFindings.setCellValueFactory(d -> new SimpleStringProperty(String.valueOf(d.getValue().getFindingsCount())));
        colCritical.setCellValueFactory(d -> new SimpleStringProperty(String.valueOf(d.getValue().getPagesTested())));

        // Action column: View Results button
        colActions.setCellFactory(col -> new TableCell<>() {
            private final Button btnView = new Button("View Results");
            {
                btnView.getStyleClass().add("ws-btn-secondary");
                btnView.setStyle("-fx-font-size: 11px; -fx-padding: 3 8;");
                btnView.setOnAction(event -> {
                    ScanRecord record = getTableView().getItems().get(getIndex());
                    if (record != null) {
                        openResultsFor(record.getId());
                    }
                });
            }

            @Override
            protected void updateItem(Void item, boolean empty) {
                super.updateItem(item, empty);
                if (empty) {
                    setGraphic(null);
                } else {
                    setGraphic(btnView);
                }
            }
        });

        // Double-click row navigates to results
        tableScanHistory.setRowFactory(tv -> {
            TableRow<ScanRecord> row = new TableRow<>();
            row.setOnMouseClicked(event -> {
                if (event.getClickCount() == 2 && !row.isEmpty()) {
                    openResultsFor(row.getItem().getId());
                }
            });
            return row;
        });
    }

    private void configureFilters() {
        cbStatusFilter.setItems(FXCollections.observableArrayList(
                "All statuses", "COMPLETED", "SCANNING", "CRAWLING", "INITIALIZING", "CANCELLED", "FAILED"
        ));
        cbStatusFilter.getSelectionModel().selectFirst();

        cbWebsiteFilter.setItems(FXCollections.observableArrayList("All websites"));
        cbWebsiteFilter.getSelectionModel().selectFirst();

        filteredList = new FilteredList<>(masterList, p -> true);

        tfSearch.textProperty().addListener((obs, oldV, newV) -> applyFilters());
        cbStatusFilter.valueProperty().addListener((obs, oldV, newV) -> applyFilters());
        cbWebsiteFilter.valueProperty().addListener((obs, oldV, newV) -> applyFilters());

        tableScanHistory.setItems(filteredList);
    }

    private void applyFilters() {
        String search = tfSearch.getText();
        String status = cbStatusFilter.getValue();
        String website = cbWebsiteFilter.getValue();

        filteredList.setPredicate(record -> {
            boolean matchesSearch = true;
            if (search != null && !search.isBlank()) {
                String term = search.toLowerCase().trim();
                boolean matchesName = record.getWebsiteName() != null &&
                        record.getWebsiteName().toLowerCase().contains(term);
                boolean matchesId = String.valueOf(record.getId()).contains(term);
                matchesSearch = matchesName || matchesId;
            }

            boolean matchesStatus = true;
            if (status != null && !status.equals("All statuses")) {
                matchesStatus = record.getStatus() != null && record.getStatus().equalsIgnoreCase(status);
            }

            boolean matchesWebsite = true;
            if (website != null && !website.equals("All websites")) {
                matchesWebsite = record.getWebsiteName() != null && record.getWebsiteName().equalsIgnoreCase(website);
            }

            return matchesSearch && matchesStatus && matchesWebsite;
        });
    }

    public void loadHistory() {
        User user = SessionManager.getInstance().getCurrentUser();
        if (user == null) return;

        Task<List<ScanRecord>> task = new Task<>() {
            @Override
            protected List<ScanRecord> call() {
                return scanService.getUserScanHistory(user.getId());
            }

            @Override
            protected void succeeded() {
                masterList.setAll(getValue());
                updateWebsiteFilterOptions(getValue());
                applyFilters();
            }

            @Override
            protected void failed() {
                log.error("Failed to load scan history", getException());
            }
        };

        Thread t = new Thread(task, "load-scan-history-worker");
        t.setDaemon(true);
        t.start();
    }

    private void updateWebsiteFilterOptions(List<ScanRecord> records) {
        Set<String> names = new HashSet<>();
        for (ScanRecord r : records) {
            if (r.getWebsiteName() != null && !r.getWebsiteName().isBlank()) {
                names.add(r.getWebsiteName());
            }
        }
        ObservableList<String> items = FXCollections.observableArrayList("All websites");
        items.addAll(names);
        cbWebsiteFilter.setItems(items);
        cbWebsiteFilter.getSelectionModel().selectFirst();
    }

    private void openResultsFor(long scanId) {
        ShellController shell = ShellController.getInstance();
        if (shell != null) {
            shell.openReportsForScan(scanId);
        } else {
            log.info("Navigating to reports for scan id={}", scanId);
        }
    }

    private String formatDuration(ScanRecord record) {
        if (record.getStartedAt() == null || record.getCompletedAt() == null) {
            return "—";
        }
        long seconds = Duration.between(record.getStartedAt(), record.getCompletedAt()).getSeconds();
        if (seconds < 60) {
            return seconds + "s";
        }
        return (seconds / 60) + "m " + (seconds % 60) + "s";
    }
}
