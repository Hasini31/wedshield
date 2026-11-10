package com.webshield.ui.controllers;

import com.webshield.api.dto.ApiExecutionDto;
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
 * Controller for browsing HTTP execution results, inspecting headers, payloads, and response codes.
 */
@Component
@Scope("prototype")
public class ApiExecutionResultsController {

    private static final Logger log = LoggerFactory.getLogger(ApiExecutionResultsController.class);

    @FXML private ComboBox<ApiScanDto> cbScans;
    @FXML private ComboBox<String> cbStatusFilter;
    @FXML private TextField tfSearch;
    @FXML private Label lblExecutionCount;

    // Pagination
    @FXML private Button btnPrevPage;
    @FXML private Button btnNextPage;
    @FXML private Label lblPageInfo;
    @FXML private ComboBox<Integer> cbPageSize;

    @FXML private TableView<ApiExecutionDto> tableExecutions;
    @FXML private TableColumn<ApiExecutionDto, String> colMethod;
    @FXML private TableColumn<ApiExecutionDto, String> colEndpoint;
    @FXML private TableColumn<ApiExecutionDto, String> colStatusCode;
    @FXML private TableColumn<ApiExecutionDto, String> colDuration;
    @FXML private TableColumn<ApiExecutionDto, String> colSize;
    @FXML private TableColumn<ApiExecutionDto, String> colOutcome;
    @FXML private TableColumn<ApiExecutionDto, String> colTimestamp;

    // Detail Inspector
    @FXML private VBox paneExecutionDetails;
    @FXML private Label lblDetailMethod;
    @FXML private Label lblDetailEndpoint;
    @FXML private Label lblDetailStatusCode;
    @FXML private Label lblDetailOutcome;
    @FXML private Label lblDetailDuration;
    @FXML private Label lblDetailUuid;
    @FXML private TextArea txtResponseHeaders;
    @FXML private TextArea txtResponseBody;

    private final ApiPersistenceService persistenceService;
    private final ObservableList<ApiExecutionDto> allLoadedList = FXCollections.observableArrayList();
    private FilteredList<ApiExecutionDto> filteredList;
    private Long preselectedScanId;

    private int currentPage = 1;
    private int pageSize = 25;

    public ApiExecutionResultsController() {
        this(SpringContext.getBean(ApiPersistenceService.class));
    }

    public ApiExecutionResultsController(ApiPersistenceService persistenceService) {
        this.persistenceService = persistenceService;
    }

    @FXML
    public void initialize() {
        configureTables();
        configureFilters();
        configurePagination();
        loadScansAsync();
    }

    private void configureTables() {
        if (colMethod != null) colMethod.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().httpMethod()));
        if (colEndpoint != null) colEndpoint.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().endpoint()));
        if (colStatusCode != null) colStatusCode.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().statusCode() > 0 ? String.valueOf(d.getValue().statusCode()) : "ERR"));
        if (colDuration != null) colDuration.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().responseTimeMs() + " ms"));
        if (colSize != null) colSize.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().responseSizeBytes() + " B"));
        if (colOutcome != null) colOutcome.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().outcome()));
        if (colTimestamp != null) colTimestamp.setCellValueFactory(d -> new SimpleStringProperty(
                d.getValue().executedAt() != null ? d.getValue().executedAt().toString().replace("T", " ") : "—"));

        if (tableExecutions != null) {
            tableExecutions.getSelectionModel().selectedItemProperty().addListener((obs, oldV, selected) -> displayDetails(selected));
        }
    }

    private void configureFilters() {
        filteredList = new FilteredList<>(allLoadedList, e -> true);

        if (cbStatusFilter != null) {
            cbStatusFilter.setItems(FXCollections.observableArrayList("ALL", "2xx (Success)", "4xx (Client Errors)", "5xx (Server Errors)", "Errors Only"));
            cbStatusFilter.setValue("ALL");
            cbStatusFilter.valueProperty().addListener((obs, oldV, newV) -> {
                currentPage = 1;
                applyFilters();
            });
        }

        if (tfSearch != null) {
            tfSearch.textProperty().addListener((obs, oldV, newV) -> {
                currentPage = 1;
                applyFilters();
            });
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
                    currentPage = 1;
                    loadExecutionsForScan(selected.id());
                }
            });
        }
    }

    private void configurePagination() {
        if (cbPageSize != null) {
            cbPageSize.setItems(FXCollections.observableArrayList(10, 25, 50, 100));
            cbPageSize.setValue(25);
            cbPageSize.valueProperty().addListener((obs, oldV, newV) -> {
                if (newV != null) {
                    pageSize = newV;
                    currentPage = 1;
                    updatePageSlice();
                }
            });
        }
    }

    private void applyFilters() {
        String filter = cbStatusFilter != null ? cbStatusFilter.getValue() : "ALL";
        String search = tfSearch != null ? tfSearch.getText() : null;
        String query = search != null ? search.trim().toLowerCase() : "";

        filteredList.setPredicate(exec -> {
            boolean statusMatches = true;
            int code = exec.statusCode();
            if ("2xx (Success)".equals(filter)) {
                statusMatches = code >= 200 && code < 300;
            } else if ("4xx (Client Errors)".equals(filter)) {
                statusMatches = code >= 400 && code < 500;
            } else if ("5xx (Server Errors)".equals(filter)) {
                statusMatches = code >= 500 && code < 600;
            } else if ("Errors Only".equals(filter)) {
                statusMatches = !"SUCCESS".equalsIgnoreCase(exec.outcome()) || code >= 400;
            }
            if (!statusMatches) return false;

            if (query.isEmpty()) return true;
            boolean epMatches = exec.endpoint() != null && exec.endpoint().toLowerCase().contains(query);
            boolean uuidMatches = exec.executionUuid() != null && exec.executionUuid().toLowerCase().contains(query);
            boolean errMatches = exec.errorMessage() != null && exec.errorMessage().toLowerCase().contains(query);
            return epMatches || uuidMatches || errMatches;
        });

        updatePageSlice();
    }

    private void updatePageSlice() {
        int total = filteredList.size();
        int totalPages = Math.max(1, (int) Math.ceil((double) total / pageSize));
        if (currentPage > totalPages) currentPage = totalPages;
        if (currentPage < 1) currentPage = 1;

        int fromIndex = (currentPage - 1) * pageSize;
        int toIndex = Math.min(fromIndex + pageSize, total);

        List<ApiExecutionDto> pageSlice = (fromIndex < total) ? filteredList.subList(fromIndex, toIndex) : List.of();
        if (tableExecutions != null) {
            tableExecutions.setItems(FXCollections.observableArrayList(pageSlice));
            if (!pageSlice.isEmpty()) {
                tableExecutions.getSelectionModel().select(0);
            }
        }

        if (lblPageInfo != null) {
            lblPageInfo.setText("Page " + currentPage + " of " + totalPages + " (" + total + " total)");
        }
        if (btnPrevPage != null) btnPrevPage.setDisable(currentPage <= 1);
        if (btnNextPage != null) btnNextPage.setDisable(currentPage >= totalPages);
        if (lblExecutionCount != null) lblExecutionCount.setText(total + " executions");
    }

    @FXML
    public void onPrevPage() {
        if (currentPage > 1) {
            currentPage--;
            updatePageSlice();
        }
    }

    @FXML
    public void onNextPage() {
        int totalPages = Math.max(1, (int) Math.ceil((double) filteredList.size() / pageSize));
        if (currentPage < totalPages) {
            currentPage++;
            updatePageSlice();
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
        Thread thread = new Thread(task, "load-execution-scans");
        thread.setDaemon(true);
        thread.start();
    }

    public void loadExecutionsForScan(Long scanId) {
        if (scanId == null || persistenceService == null) return;
        User user = SessionManager.getInstance().getCurrentUser();
        Long userId = user != null ? user.getId() : 1L;

        Task<List<ApiExecutionDto>> task = new Task<>() {
            @Override
            protected List<ApiExecutionDto> call() {
                return persistenceService.getExecutionsForScan(scanId, userId);
            }

            @Override
            protected void succeeded() {
                allLoadedList.setAll(getValue());
                applyFilters();
            }
        };
        Thread thread = new Thread(task, "load-executions");
        thread.setDaemon(true);
        thread.start();
    }

    private void displayDetails(ApiExecutionDto exec) {
        if (exec == null) {
            if (paneExecutionDetails != null) paneExecutionDetails.setVisible(false);
            return;
        }
        if (paneExecutionDetails != null) paneExecutionDetails.setVisible(true);

        if (lblDetailMethod != null) lblDetailMethod.setText(exec.httpMethod());
        if (lblDetailEndpoint != null) lblDetailEndpoint.setText(exec.endpoint());
        if (lblDetailStatusCode != null) {
            lblDetailStatusCode.setText("HTTP " + exec.statusCode());
            lblDetailStatusCode.getStyleClass().removeAll("ws-badge-success", "ws-badge-warning", "ws-badge-danger");
            if (exec.statusCode() >= 200 && exec.statusCode() < 300) {
                lblDetailStatusCode.getStyleClass().add("ws-badge-success");
            } else if (exec.statusCode() >= 400 && exec.statusCode() < 500) {
                lblDetailStatusCode.getStyleClass().add("ws-badge-warning");
            } else {
                lblDetailStatusCode.getStyleClass().add("ws-badge-danger");
            }
        }
        if (lblDetailOutcome != null) lblDetailOutcome.setText(exec.outcome());
        if (lblDetailDuration != null) lblDetailDuration.setText(exec.responseTimeMs() + " ms (" + exec.responseSizeBytes() + " bytes)");
        if (lblDetailUuid != null) lblDetailUuid.setText("UUID: " + exec.executionUuid());

        if (txtResponseHeaders != null) {
            txtResponseHeaders.setText(exec.responseHeaders() != null && !exec.responseHeaders().isBlank()
                    ? exec.responseHeaders() : "(No headers recorded)");
        }

        if (txtResponseBody != null) {
            String body = exec.responseBody() != null && !exec.responseBody().isBlank()
                    ? exec.responseBody() : "(Empty response body)";
            if (exec.bodyTruncated()) {
                body += "\n\n[NOTICE: Response truncated for storage safety]";
            }
            txtResponseBody.setText(body);
        }
    }
}

