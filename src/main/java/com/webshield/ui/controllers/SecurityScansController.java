package com.webshield.ui.controllers;

import com.webshield.auth.SessionManager;
import com.webshield.models.SecurityFinding;
import com.webshield.models.User;
import com.webshield.models.Website;
import com.webshield.scan.*;
import com.webshield.website.WebsiteService;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

/**
 * Controller for configuring and running automated security assessments.
 */
@Component
@Scope("prototype")
public class SecurityScansController {

    private static final Logger log = LoggerFactory.getLogger(SecurityScansController.class);
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    @FXML private ComboBox<Website> cbWebsite;
    @FXML private Spinner<Integer> spDepth;
    @FXML private Spinner<Integer> spMaxPages;
    @FXML private Spinner<Integer> spTimeout;

    @FXML private CheckBox chkHeaders;
    @FXML private CheckBox chkCookies;
    @FXML private CheckBox chkReflection;
    @FXML private CheckBox chkSqlErrors;
    @FXML private CheckBox chkInputValidation;

    @FXML private Button btnStartScan;
    @FXML private Button btnStopScan;
    @FXML private Label lblScanStatus;
    @FXML private ProgressBar progressBar;
    @FXML private Label lblProgressPct;
    @FXML private Label lblPagesFound;
    @FXML private Label lblPagesTested;
    @FXML private Label lblChecksDone;
    @FXML private Label lblFindingsFound;
    @FXML private TextArea taLog;

    private final WebsiteService websiteService;
    private final ScanService scanService;

    private Long preselectedWebsiteId;
    private volatile long activeScanId = 0;
    private CompletableFuture<ScanExecutionResult> currentScanFuture;

    public SecurityScansController() {
        this(com.webshield.config.SpringContext.getBean(WebsiteService.class),
             com.webshield.config.SpringContext.getBean(ScanService.class));
    }

    public SecurityScansController(WebsiteService websiteService, ScanService scanService) {
        this.websiteService = websiteService != null ? websiteService : new WebsiteService();
        this.scanService = scanService != null ? scanService : new ScanService();
    }

    @FXML
    public void initialize() {
        configureSpinners();
        loadWebsites();
        cbWebsite.setOnShowing(event -> loadWebsites());
    }

    private void configureSpinners() {
        if (spDepth.getValueFactory() == null) {
            spDepth.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 10, 3));
        }
        if (spMaxPages.getValueFactory() == null) {
            spMaxPages.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(10, 500, 50));
        }
        if (spTimeout.getValueFactory() == null) {
            spTimeout.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(5, 60, 15));
        }
    }

    private void loadWebsites() {
        Website currentSelection = cbWebsite.getSelectionModel().getSelectedItem();
        List<Website> websites = websiteService.getUserWebsites();
        cbWebsite.setItems(FXCollections.observableArrayList(websites));

        if (currentSelection != null) {
            for (Website w : websites) {
                if (w.getId() == currentSelection.getId()) {
                    cbWebsite.getSelectionModel().select(w);
                    return;
                }
            }
        }

        if (preselectedWebsiteId != null) {
            for (Website w : websites) {
                if (w.getId() == preselectedWebsiteId) {
                    cbWebsite.getSelectionModel().select(w);
                    break;
                }
            }
        } else if (!websites.isEmpty()) {
            cbWebsite.getSelectionModel().selectFirst();
        }
    }

    public void selectWebsite(long websiteId) {
        this.preselectedWebsiteId = websiteId;
        if (cbWebsite != null && cbWebsite.getItems() != null) {
            for (Website w : cbWebsite.getItems()) {
                if (w.getId() == websiteId) {
                    cbWebsite.getSelectionModel().select(w);
                    break;
                }
            }
        }
    }

    @FXML
    private void onStartScan() {
        Website target = cbWebsite.getSelectionModel().getSelectedItem();
        if (target == null) {
            logMessage("Error: Please select a registered target website.");
            return;
        }

        User user = SessionManager.getInstance().getCurrentUser();
        if (user == null) {
            logMessage("Error: User session expired. Please sign in again.");
            return;
        }

        boolean headers = chkHeaders.isSelected();
        boolean cookies = chkCookies.isSelected();
        boolean reflection = chkReflection.isSelected();
        boolean sql = chkSqlErrors.isSelected();
        boolean inputVal = chkInputValidation.isSelected();

        if (!headers && !cookies && !reflection && !sql && !inputVal) {
            logMessage("Error: At least one assessment category must be selected.");
            return;
        }

        ScanConfiguration config = new ScanConfiguration(target.getId(), target.getName(), target.getUrl(), user.getId())
                .setCrawlDepth(spDepth.getValue())
                .setMaxPages(spMaxPages.getValue())
                .setTimeoutSeconds(spTimeout.getValue())
                .setCheckHeaders(headers)
                .setCheckCookies(cookies)
                .setCheckReflection(reflection)
                .setCheckSqlErrors(sql)
                .setCheckInputValidation(inputVal);

        // UI state setup
        btnStartScan.setDisable(true);
        btnStopScan.setDisable(false);
        lblScanStatus.setText("STATUS: INITIALIZING");
        progressBar.setProgress(0);
        lblProgressPct.setText("0%");
        lblPagesFound.setText("0");
        lblPagesTested.setText("0");
        lblChecksDone.setText("0");
        lblFindingsFound.setText("0");
        taLog.clear();

        logMessage("Initializing Security Assessment against " + target.getName() + " (" + target.getUrl() + ")");

        ScanProgressTracker tracker = new ScanProgressTracker();
        tracker.addListener(t -> Platform.runLater(() -> {
            progressBar.setProgress(t.getProgressPercentage());
            lblProgressPct.setText((int)(t.getProgressPercentage() * 100) + "%");
            lblScanStatus.setText("STATUS: " + t.getStatus().getDisplayName().toUpperCase());
            lblPagesFound.setText(String.valueOf(t.getPagesDiscovered()));
            lblPagesTested.setText(String.valueOf(t.getPagesTested()));
            lblChecksDone.setText(String.valueOf(t.getChecksCompleted()));
            lblFindingsFound.setText(String.valueOf(t.getFindingsGenerated()));
            if (!t.getCurrentOperation().isBlank()) {
                logMessage(t.getCurrentOperation());
            }
        }));

        currentScanFuture = scanService.startScan(config, tracker);
        currentScanFuture.thenAcceptAsync(result -> {
            activeScanId = result.getScanId();
            cleanupScanUI(result.getFinalStatus().name());
            lblPagesFound.setText(String.valueOf(result.getPagesDiscovered()));
            lblPagesTested.setText(String.valueOf(result.getPagesTested()));
            lblFindingsFound.setText(String.valueOf(result.getFindingsCount()));
            progressBar.setProgress(1.0);
            lblProgressPct.setText("100%");
            logMessage("Assessment completed with status: " + result.getFinalStatus());
            logMessage("Summary: " + result.getFindingsCount() + " findings (Critical: " +
                    result.getCriticalFindings() + ", High: " + result.getHighFindings() +
                    ", Medium: " + result.getMediumFindings() + ", Low: " + result.getLowFindings() + ")");
            for (SecurityFinding sf : result.getFindings()) {
                logMessage("[" + sf.getSeverity() + "] " + sf.getFindingName() + " (" + sf.getAffectedUrl() + ")");
            }
        }, Platform::runLater).exceptionallyAsync(ex -> {
            cleanupScanUI("FAILED");
            logMessage("Assessment failed: " + ex.getMessage());
            log.error("Assessment failed", ex);
            return null;
        }, Platform::runLater);
    }

    @FXML
    private void onStopScan() {
        if (activeScanId > 0) {
            scanService.cancelScan(activeScanId);
            logMessage("Cancellation signal dispatched for scan ID: " + activeScanId);
        } else if (currentScanFuture != null) {
            currentScanFuture.cancel(true);
            logMessage("Cancellation signal dispatched to background worker.");
        }
        cleanupScanUI("CANCELLED");
    }

    private void cleanupScanUI(String status) {
        btnStartScan.setDisable(false);
        btnStopScan.setDisable(true);
        lblScanStatus.setText("STATUS: " + status);
        logMessage("Assessment state finalized: " + status);
    }

    private void logMessage(String msg) {
        String entry = "[" + LocalDateTime.now().format(TIME_FMT) + "] " + msg + "\n";
        Platform.runLater(() -> {
            if (taLog != null) {
                taLog.appendText(entry);
            }
        });
    }
}
