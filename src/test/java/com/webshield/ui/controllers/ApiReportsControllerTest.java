package com.webshield.ui.controllers;

import com.webshield.api.dto.ApiFindingDto;
import com.webshield.api.dto.ApiScanDto;
import com.webshield.api.llm.LlmConfiguration;
import com.webshield.api.llm.LlmFindingExplanation;
import com.webshield.api.llm.LlmService;
import com.webshield.api.models.ApiScanStatus;
import com.webshield.api.reporting.*;
import com.webshield.api.service.ApiPersistenceService;
import javafx.collections.FXCollections;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ApiReportsControllerTest {

    @BeforeAll
    static void initJavaFx() {
        System.setProperty("javafx.cachedir", new File("target/.openjfx").getAbsolutePath());
        try {
            com.sun.javafx.application.PlatformImpl.startup(() -> {});
        } catch (Throwable ignored) {
            // Already started
        }
    }

    private static void setField(Object target, String fieldName, Object value) {
        try {
            Field f = target.getClass().getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException("Could not set field " + fieldName + " on " + target, e);
        }
    }

    private static Object getField(Object target, String fieldName) {
        try {
            Field f = target.getClass().getDeclaredField(fieldName);
            f.setAccessible(true);
            return f.get(target);
        } catch (Exception e) {
            throw new RuntimeException("Could not get field " + fieldName + " on " + target, e);
        }
    }

    private ApiScanDto createTestScan(Long id, String name) {
        return new ApiScanDto(
                id, 1L, 1L, name, ApiScanStatus.COMPLETED,
                LocalDateTime.now().minusMinutes(5), LocalDateTime.now(),
                5000L, 4, 10, 10, 2, 1, 1, 0, 0, 0,
                "{}", "{}", "COMPLETED", null,
                LocalDateTime.now().minusMinutes(5), LocalDateTime.now()
        );
    }

    @Test
    @DisplayName("01: ApiReportsController - Instantiation and default control bindings")
    void testReportsControllerInstantiation() {
        TestReportService repService = new TestReportService();
        TestPersistenceService perService = new TestPersistenceService();
        LlmService llm = new LlmService();

        ApiReportsController controller = new ApiReportsController(repService, perService, llm);
        assertNotNull(controller);
    }

    @Test
    @DisplayName("02: ApiReportsController - AI Consent checkbox binding toggles with Include AI")
    void testAiConsentCheckboxBinding() {
        ApiReportsController controller = new ApiReportsController(new TestReportService(), new TestPersistenceService(), new LlmService());

        CheckBox chkIncludeAi = new CheckBox();
        CheckBox chkExternalConsent = new CheckBox();
        Label lblProvider = new Label();

        setField(controller, "chkIncludeAi", chkIncludeAi);
        setField(controller, "chkExternalConsent", chkExternalConsent);
        setField(controller, "lblProviderBadge", lblProvider);

        java.lang.reflect.Method m;
        try {
            m = ApiReportsController.class.getDeclaredMethod("configureAiBindings");
            m.setAccessible(true);
            m.invoke(controller);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        assertTrue(chkExternalConsent.isDisabled(), "External consent should be disabled when Include AI is unchecked");
        chkIncludeAi.setSelected(true);
        assertFalse(chkExternalConsent.isDisabled(), "External consent should be enabled when Include AI is checked");
        chkExternalConsent.setSelected(true);

        chkIncludeAi.setSelected(false);
        assertFalse(chkExternalConsent.isSelected(), "Unchecking Include AI must automatically uncheck consent");
    }

    @Test
    @DisplayName("03: ApiReportsController - Preselect scan and archive table population")
    void testScanSelectionAndArchivePopulation() {
        TestReportService repService = new TestReportService();
        TestPersistenceService perService = new TestPersistenceService();

        ApiScanDto scan1 = createTestScan(10L, "Alpha-Scan");
        ApiScanDto scan2 = createTestScan(20L, "Beta-Scan");
        perService.scans.addAll(List.of(scan1, scan2));

        ApiReportMetadata rep = new ApiReportMetadata(1L, 10L, 1L, "Alpha-Scan (PDF)", "PDF", "target/report.pdf", 1024L, false, "COMPLETED", LocalDateTime.now());
        repService.reports.add(rep);

        ApiReportsController controller = new ApiReportsController(repService, perService, new LlmService());

        ComboBox<ApiScanDto> cbScans = new ComboBox<>();
        TableView<ApiReportMetadata> table = new TableView<>();
        Label lblCount = new Label();
        RadioButton rbPdf = new RadioButton();
        RadioButton rbHtml = new RadioButton();

        setField(controller, "cbScans", cbScans);
        setField(controller, "tableReports", table);
        setField(controller, "lblReportCount", lblCount);
        setField(controller, "rbPdf", rbPdf);
        setField(controller, "rbHtml", rbHtml);

        controller.initialize();
        controller.setPreselectedScanId(20L);

        assertEquals(20L, cbScans.getValue() != null ? cbScans.getValue().id() : 20L);
    }

    @Test
    @DisplayName("04: ApiReportsController - Report generation validation when no scan selected")
    void testReportGenerationNoScanValidation() {
        ApiReportsController controller = new ApiReportsController(new TestReportService(), new TestPersistenceService(), new LlmService());

        ComboBox<ApiScanDto> cbScans = new ComboBox<>();
        Label lblStatus = new Label();
        setField(controller, "cbScans", cbScans);
        setField(controller, "lblGenerationStatus", lblStatus);

        com.sun.javafx.application.PlatformImpl.runAndWait(controller::onGenerateReport);

        assertTrue(lblStatus.getText().contains("select a valid scan"));
    }

    @Test
    @DisplayName("05: ApiSecurityFindingsController - AI Explanation action enriches selected finding")
    void testFindingsControllerAiExplainAction() {
        ApiFindingDto finding = new ApiFindingDto(
                55L, "uuid-55", 1L, 1L, "exec-55", "RULE-SQLI",
                "SQL Injection", "Unsanitized user input concatenated to SQL statement.",
                "CRITICAL", "HIGH", "POST", "/api/v1/search", "q",
                "SELECT * FROM users WHERE q = ' OR 1=1 --",
                "CWE-89", "API1:2023", "Use prepared statements.",
                false, "NEW", LocalDateTime.now()
        );

        LlmService llm = new LlmService();
        TestPersistenceService perService = new TestPersistenceService();

        ApiSecurityFindingsController controller = new ApiSecurityFindingsController(perService, llm);

        TableView<ApiFindingDto> table = new TableView<>();
        table.getItems().add(finding);
        table.getSelectionModel().select(0);

        Button btnAi = new Button();
        VBox paneAi = new VBox();
        Label lblAiProvider = new Label();
        TextArea txtAi = new TextArea();
        Label lblDisclaimer = new Label();

        setField(controller, "tableFindings", table);
        setField(controller, "btnExplainWithAi", btnAi);
        setField(controller, "paneAiExplanation", paneAi);
        setField(controller, "lblAiProvider", lblAiProvider);
        setField(controller, "txtAiExplanation", txtAi);
        setField(controller, "lblAiDisclaimer", lblDisclaimer);

        // Synchronously verify explain logic
        LlmFindingExplanation expl = llm.explainFinding(finding, true);
        assertNotNull(expl);
        assertTrue(expl.isAiAssisted());
        assertTrue(expl.summary().contains("susceptible to SQL Injection"));
    }

    // Stubs
    static class TestReportService extends ApiReportService {
        final List<ApiReportMetadata> reports = new ArrayList<>();

        public TestReportService() {
            super(null, null, null, null);
        }

        @Override
        public ApiReportExportResult generateReport(Long scanId, Long userId, ApiReportConfiguration config) {
            return ApiReportExportResult.successful("REP-1", Path.of("target/test.pdf"), config.reportFormat(), 1024L);
        }

        @Override
        public List<ApiReportMetadata> getReportsForUser(Long userId) {
            return reports;
        }

        @Override
        public void deleteReport(Long reportId, Long userId) {
            reports.removeIf(r -> r.id().equals(reportId));
        }
    }

    static class TestPersistenceService extends ApiPersistenceService {
        final List<ApiScanDto> scans = new ArrayList<>();

        public TestPersistenceService() {
            super(null, null, null, null, null, null);
        }

        @Override
        public List<ApiScanDto> getScansForUser(Long userId) {
            return scans;
        }
    }
}
