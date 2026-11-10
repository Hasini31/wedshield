package com.wedshield.ui;

import com.wedshield.analysis.SecurityAssessmentEngine;
import com.wedshield.model.AssessmentReport;
import com.wedshield.model.AssessmentRequest;
import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.util.List;

public class WedShieldApp extends Application {
    private final SecurityAssessmentEngine engine = new SecurityAssessmentEngine();

    @Override
    public void start(Stage stage) {
        TextField target = new TextField("https://example.com");
        TextArea openApi = new TextArea("/pets:\n  get:\n");
        TextArea crawlHtml = new TextArea("<a href=\"/admin\">admin</a>");
        TextArea output = new TextArea();
        output.setEditable(false);

        Button run = new Button("Run assessment");
        run.setOnAction(event -> {
            AssessmentReport report = engine.assess(new AssessmentRequest(
                    target.getText(),
                    openApi.getText(),
                    crawlHtml.getText(),
                    List.of()
            ));
            output.setText(formatReport(report));
        });

        VBox root = new VBox(10, target, openApi, crawlHtml, run, output);
        root.setPadding(new Insets(12));
        stage.setScene(new Scene(root, 800, 600));
        stage.setTitle("WedShield");
        stage.show();
    }

    private String formatReport(AssessmentReport report) {
        return "Mutations: " + report.openApiMutations().size() + "\n"
                + "Crawled URLs: " + report.crawledUrls().size() + "\n"
                + "Findings: " + report.findings().size() + "\n"
                + "New findings: " + report.regression().newFindings().size() + "\n"
                + "Resolved findings: " + report.regression().resolvedFindings().size();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
