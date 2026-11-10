package com.webshield.ui.controllers;

import com.webshield.crawler.*;
import com.webshield.models.Website;
import com.webshield.website.WebsiteService;
import com.webshield.website.WebsiteSummary;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

/**
 * Controller for viewing website details, running crawler discovery,
 * and visualizing the discovered website hierarchy in a TreeView.
 */
@Component
@Scope("prototype")
public class WebsiteDetailsController {

    private static final Logger log = LoggerFactory.getLogger(WebsiteDetailsController.class);

    @FXML private Label lblWebsiteName;
    @FXML private Label lblWebsiteUrl;
    @FXML private Label statPages;
    @FXML private Label statForms;
    @FXML private Label statInputs;
    @FXML private Label statStatus;

    @FXML private Button btnCrawl;
    @FXML private Button btnStartScan;

    @FXML private VBox crawlProgressBox;
    @FXML private Label lblCrawlStatus;
    @FXML private Label lblCrawlMetrics;
    @FXML private ProgressBar crawlProgressBar;

    @FXML private TreeView<String> treeStructure;
    @FXML private TableView<DiscoveredPage> tablePages;
    @FXML private TableColumn<DiscoveredPage, String> colPageUrl;
    @FXML private TableColumn<DiscoveredPage, String> colPageStatus;
    @FXML private TableColumn<DiscoveredPage, String> colPageMethod;
    @FXML private TableColumn<DiscoveredPage, String> colPageDepth;
    @FXML private TableColumn<DiscoveredPage, String> colPageForms;

    private final WebsiteService websiteService;
    private final CrawlManager crawlManager;
    private long websiteId;
    private Website website;

    public WebsiteDetailsController() {
        this(com.webshield.config.SpringContext.getBean(WebsiteService.class),
             com.webshield.config.SpringContext.getBean(CrawlManager.class));
    }

    public WebsiteDetailsController(WebsiteService websiteService, CrawlManager crawlManager) {
        this.websiteService = websiteService != null ? websiteService : new WebsiteService();
        this.crawlManager = crawlManager != null ? crawlManager : new CrawlManager();
    }

    @FXML
    public void initialize() {
        configurePageTable();
    }

    private void configurePageTable() {
        colPageUrl.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().getUrl()));
        colPageStatus.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(String.valueOf(d.getValue().getStatusCode())));
        colPageMethod.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(d.getValue().getHttpMethod()));
        colPageDepth.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(String.valueOf(d.getValue().getDepth())));
        colPageForms.setCellValueFactory(d -> new javafx.beans.property.SimpleStringProperty(String.valueOf(d.getValue().getForms().size())));
    }

    public void loadWebsite(long id) {
        this.websiteId = id;
        Optional<Website> opt = websiteService.getWebsite(id);
        if (opt.isEmpty()) {
            lblWebsiteName.setText("Website Not Found");
            return;
        }

        this.website = opt.get();
        lblWebsiteName.setText(website.getName());
        lblWebsiteUrl.setText(website.getUrl());

        refreshMetrics();
        loadDiscoveredStructure();
    }

    private void refreshMetrics() {
        Optional<WebsiteSummary> summaryOpt = websiteService.getWebsiteSummary(websiteId);
        if (summaryOpt.isPresent()) {
            WebsiteSummary s = summaryOpt.get();
            statPages.setText(String.valueOf(s.getTotalPages()));
            statForms.setText(String.valueOf(s.getTotalForms()));
            statInputs.setText(String.valueOf(s.getTotalInputFields()));
            statStatus.setText(s.getLastScanStatus());
        }
    }

    private void loadDiscoveredStructure() {
        Task<List<DiscoveredPage>> loadTask = new Task<>() {
            @Override
            protected List<DiscoveredPage> call() {
                return crawlManager.getDiscoveredPages(websiteId);
            }

            @Override
            protected void succeeded() {
                List<DiscoveredPage> pages = getValue();
                tablePages.setItems(FXCollections.observableArrayList(pages));
                buildTreeStructure(pages);
            }
        };

        Thread t = new Thread(loadTask, "load-structure");
        t.setDaemon(true);
        t.start();
    }

    private void buildTreeStructure(List<DiscoveredPage> pages) {
        String rootLabel = website != null ? website.getUrl() : "Target Website";
        TreeItem<String> rootItem = new TreeItem<>(rootLabel);
        rootItem.setExpanded(true);

        for (DiscoveredPage page : pages) {
            String path = extractPath(page.getUrl());
            TreeItem<String> pageItem = new TreeItem<>("📄 " + path + " (" + page.getStatusCode() + ")");

            for (DiscoveredForm form : page.getForms()) {
                TreeItem<String> formItem = new TreeItem<>("📝 " + form.getFormMethod() + " " + extractPath(form.getFormAction()));
                for (DiscoveredField field : form.getFields()) {
                    formItem.getChildren().add(new TreeItem<>("⌨ " + field.getName() + " [" + field.getType() + "]"));
                }
                pageItem.getChildren().add(formItem);
            }

            rootItem.getChildren().add(pageItem);
        }

        treeStructure.setRoot(rootItem);
    }

    private String extractPath(String url) {
        try {
            URI uri = new URI(url);
            String p = uri.getPath();
            return (p == null || p.isEmpty()) ? "/" : p;
        } catch (Exception e) {
            return url;
        }
    }

    @FXML
    private void onCrawlWebsite() {
        if (website == null) return;

        crawlProgressBox.setVisible(true);
        crawlProgressBox.setManaged(true);
        crawlProgressBar.setProgress(-1); // Indeterminate
        lblCrawlStatus.setText("Crawling target " + website.getUrl() + "...");
        btnCrawl.setDisable(true);

        CrawlConfiguration config = new CrawlConfiguration(website.getUrl())
                .setMaxDepth(3)
                .setMaxPages(50)
                .setRequestTimeoutSeconds(10)
                .setAllowLocalhost(true); // Allow local development targets

        Task<CrawlResult> crawlTask = new Task<>() {
            @Override
            protected CrawlResult call() {
                return crawlManager.crawlAndPersist(websiteId, config, (pages, forms, currentUrl) -> {
                    Platform.runLater(() -> {
                        lblCrawlMetrics.setText(pages + " pages, " + forms + " forms");
                        lblCrawlStatus.setText("Visiting: " + truncate(currentUrl, 50));
                    });
                });
            }

            @Override
            protected void succeeded() {
                CrawlResult result = getValue();
                btnCrawl.setDisable(false);
                crawlProgressBar.setProgress(1.0);
                lblCrawlStatus.setText("Crawl Complete: Discovered " + result.getTotalPages() + " pages and " + result.getTotalForms() + " forms (" + result.getDurationMs() + "ms).");
                refreshMetrics();
                loadDiscoveredStructure();
            }

            @Override
            protected void failed() {
                btnCrawl.setDisable(false);
                crawlProgressBar.setProgress(0);
                lblCrawlStatus.setText("Crawl Failed: " + getException().getMessage());
                log.error("Crawl failed", getException());
            }
        };

        Thread t = new Thread(crawlTask, "web-crawler-runner");
        t.setDaemon(true);
        t.start();
    }

    @FXML
    private void onStartSecurityScan() {
        if (ShellController.getInstance() != null) {
            ShellController.getInstance().openSecurityScansFor(websiteId);
        }
    }

    @FXML
    private void onBack() {
        if (ShellController.getInstance() != null) {
            ShellController.getInstance().openWebsites();
        }
    }

    private String truncate(String str, int max) {
        if (str == null) return "";
        return str.length() > max ? str.substring(0, max) + "..." : str;
    }
}

