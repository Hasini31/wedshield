package com.webshield.ui.dialogs;

import com.webshield.config.SpringContext;
import com.webshield.website.reporting.WebsiteAiReportService;
import com.webshield.website.reporting.WebsiteReportPdfWriter;
import com.webshield.website.reporting.WebsiteReportResult;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.file.Path;

/**
 * Professional dialog for generating, viewing, and exporting Google Gemini AI security reports.
 */
public class AiReportViewerDialog {

    private static final Logger log = LoggerFactory.getLogger(AiReportViewerDialog.class);

    public static void show(long scanId, Stage ownerStage) {
        Stage stage = new Stage();
        stage.initModality(Modality.APPLICATION_MODAL);
        if (ownerStage != null) {
            stage.initOwner(ownerStage);
        }
        stage.setTitle("WebShield – AI Security Report (Scan #" + scanId + ")");
        stage.setMinWidth(850);
        stage.setMinHeight(620);

        BorderPane root = new BorderPane();
        root.setStyle("-fx-background-color: #F8FAFC;");

        // Header
        VBox headerBox = new VBox(4);
        headerBox.setStyle("-fx-background-color: #0F172A; -fx-padding: 16 24;");
        Label lblTitle = new Label("🛡️ AI Security Assessment Report");
        lblTitle.setStyle("-fx-font-size: 18px; -fx-font-weight: bold; -fx-text-fill: white;");
        Label lblSubtitle = new Label("Google Gemini Live Threat Analysis & Executive Remediation Plan for Scan #" + scanId);
        lblSubtitle.setStyle("-fx-font-size: 12px; -fx-text-fill: #94A3B8;");
        headerBox.getChildren().addAll(lblTitle, lblSubtitle);
        root.setTop(headerBox);

        // Center: Progress View vs Report View
        StackPane contentStack = new StackPane();
        contentStack.setPadding(new Insets(16, 24, 16, 24));

        // Loading Indicator Box
        VBox loadingBox = new VBox(16);
        loadingBox.setAlignment(Pos.CENTER);
        ProgressIndicator progress = new ProgressIndicator();
        progress.setPrefSize(48, 48);
        Label lblProgress = new Label("Google Gemini is analyzing scan data and compiling report...");
        lblProgress.setStyle("-fx-font-size: 14px; -fx-font-weight: bold; -fx-text-fill: #1E293B;");
        Label lblSubProgress = new Label("Extracting verified findings, categorizing attack vectors, and assembling the 10-section report.");
        lblSubProgress.setStyle("-fx-font-size: 12px; -fx-text-fill: #64748B;");
        loadingBox.getChildren().addAll(progress, lblProgress, lblSubProgress);

        // Result Box
        VBox resultBox = new VBox(12);
        resultBox.setVisible(false);

        HBox metaBar = new HBox(12);
        metaBar.setAlignment(Pos.CENTER_LEFT);
        Label lblModelBadge = new Label("Powered by Google Gemini (gemini-1.5-flash)");
        lblModelBadge.setStyle("-fx-background-color: #EFF6FF; -fx-text-fill: #2563EB; -fx-font-weight: bold; -fx-font-size: 11px; -fx-padding: 4 10; -fx-background-radius: 4; -fx-border-color: #BFDBFE; -fx-border-radius: 4;");
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        Label lblNotice = new Label("Confidential Security Assessment Document");
        lblNotice.setStyle("-fx-text-fill: #94A3B8; -fx-font-size: 11px;");
        metaBar.getChildren().addAll(lblModelBadge, spacer, lblNotice);

        TextArea txtReport = new TextArea();
        txtReport.setEditable(false);
        txtReport.setWrapText(true);
        txtReport.setStyle("-fx-font-family: 'Consolas', 'Courier New', monospace; -fx-font-size: 12px; -fx-control-inner-background: #FFFFFF; -fx-border-color: #CBD5E1; -fx-border-radius: 4;");
        VBox.setVgrow(txtReport, Priority.ALWAYS);

        resultBox.getChildren().addAll(metaBar, txtReport);

        contentStack.getChildren().addAll(loadingBox, resultBox);
        root.setCenter(contentStack);

        // Bottom Action Bar
        HBox bottomBar = new HBox(12);
        bottomBar.setAlignment(Pos.CENTER_RIGHT);
        bottomBar.setStyle("-fx-background-color: #FFFFFF; -fx-border-color: #E2E8F0; -fx-border-width: 1 0 0 0; -fx-padding: 12 24;");

        Button btnDownloadPdf = new Button("⬇ Download as PDF");
        btnDownloadPdf.setStyle("-fx-background-color: #2563EB; -fx-text-fill: white; -fx-font-weight: bold; -fx-padding: 8 16; -fx-background-radius: 4; -fx-cursor: hand;");
        btnDownloadPdf.setDisable(true);

        Button btnCopy = new Button("📋 Copy Report");
        btnCopy.setStyle("-fx-background-color: #F1F5F9; -fx-text-fill: #334155; -fx-font-weight: bold; -fx-padding: 8 14; -fx-background-radius: 4; -fx-border-color: #CBD5E1; -fx-border-radius: 4; -fx-cursor: hand;");
        btnCopy.setDisable(true);

        Button btnClose = new Button("Close");
        btnClose.setStyle("-fx-background-color: #F1F5F9; -fx-text-fill: #334155; -fx-padding: 8 14; -fx-background-radius: 4; -fx-border-color: #CBD5E1; -fx-border-radius: 4; -fx-cursor: hand;");
        btnClose.setOnAction(e -> stage.close());

        bottomBar.getChildren().addAll(btnCopy, btnDownloadPdf, btnClose);
        root.setBottom(bottomBar);

        Scene scene = new Scene(root, 900, 680);
        stage.setScene(scene);
        stage.show();

        // Background Generation Task
        WebsiteAiReportService reportService = SpringContext.getBean(WebsiteAiReportService.class) != null
                ? SpringContext.getBean(WebsiteAiReportService.class) : new WebsiteAiReportService();

        Task<WebsiteReportResult> task = new Task<>() {
            @Override
            protected WebsiteReportResult call() throws Exception {
                return reportService.generateWebsiteAiReport(scanId);
            }

            @Override
            protected void succeeded() {
                WebsiteReportResult res = getValue();
                Platform.runLater(() -> {
                    loadingBox.setVisible(false);
                    resultBox.setVisible(true);
                    txtReport.setText(res.reportText());
                    btnDownloadPdf.setDisable(false);
                    btnCopy.setDisable(false);

                    btnDownloadPdf.setOnAction(ev -> {
                        FileChooser fileChooser = new FileChooser();
                        fileChooser.setTitle("Save Security Assessment PDF");
                        String safeName = res.website().getName().replaceAll("[^a-zA-Z0-9_.-]", "_");
                        fileChooser.setInitialFileName("WebShield_Report_Scan_" + scanId + "_" + safeName + ".pdf");
                        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PDF Document (*.pdf)", "*.pdf"));
                        File saveFile = fileChooser.showSaveDialog(stage);
                        if (saveFile != null) {
                            try {
                                WebsiteReportPdfWriter.writePdf(res, saveFile.toPath());
                                Alert alert = new Alert(Alert.AlertType.INFORMATION);
                                alert.setTitle("PDF Generated Successfully");
                                alert.setHeaderText("Report Downloaded");
                                alert.setContentText("The 10-section security assessment report was successfully exported to:\n" + saveFile.getAbsolutePath());
                                alert.showAndWait();
                            } catch (Exception ex) {
                                log.error("Failed to write PDF", ex);
                                Alert alert = new Alert(Alert.AlertType.ERROR);
                                alert.setTitle("PDF Export Error");
                                alert.setHeaderText("Failed to create PDF");
                                alert.setContentText("Error details: " + ex.getMessage());
                                alert.showAndWait();
                            }
                        }
                    });

                    btnCopy.setOnAction(ev -> {
                        ClipboardContent content = new ClipboardContent();
                        content.putString(res.reportText());
                        Clipboard.getSystemClipboard().setContent(content);
                        btnCopy.setText("✓ Copied!");
                    });
                });
            }

            @Override
            protected void failed() {
                Throwable ex = getException();
                log.error("AI report generation failed for scan #{}", scanId, ex);
                Platform.runLater(() -> {
                    loadingBox.setVisible(false);
                    VBox errorBox = new VBox(12);
                    errorBox.setAlignment(Pos.CENTER);
                    Label errIcon = new Label("⚠️");
                    errIcon.setStyle("-fx-font-size: 36px;");
                    Label errTitle = new Label("AI Report Generation Failed");
                    errTitle.setStyle("-fx-font-size: 16px; -fx-font-weight: bold; -fx-text-fill: #DC2626;");
                    Label errDesc = new Label(ex != null ? ex.getMessage() : "Unknown error while communicating with Gemini API.");
                    errDesc.setStyle("-fx-font-size: 13px; -fx-text-fill: #475569; -fx-wrap-text: true; -fx-max-width: 650; -fx-alignment: center;");
                    errorBox.getChildren().addAll(errIcon, errTitle, errDesc);
                    contentStack.getChildren().add(errorBox);
                });
            }
        };

        Thread t = new Thread(task, "gemini-report-worker-" + scanId);
        t.setDaemon(true);
        t.start();
    }
}
