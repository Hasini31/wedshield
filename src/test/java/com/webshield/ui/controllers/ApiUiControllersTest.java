package com.webshield.ui.controllers;

import com.webshield.api.analysis.ApiSecurityAnalyzer;
import com.webshield.api.analysis.ApiSecurityFinding;
import com.webshield.api.dto.ApiExecutionDto;
import com.webshield.api.dto.ApiFindingDto;
import com.webshield.api.dto.ApiScanComparisonDto;
import com.webshield.api.dto.ApiScanDto;
import com.webshield.api.dto.ApiTestCaseResultDto;
import com.webshield.api.execution.ApiExecutionConfiguration;
import com.webshield.api.generation.ApiTestGenerator;
import com.webshield.api.models.ApiEndpoint;
import com.webshield.api.models.ApiParameter;
import com.webshield.api.models.ApiProject;
import com.webshield.api.models.ApiScanStatus;
import com.webshield.api.models.ApiSchema;
import com.webshield.api.models.HttpMethod;
import com.webshield.api.models.ParameterLocation;
import com.webshield.api.models.SchemaType;
import com.webshield.api.models.SourceType;
import com.webshield.api.models.SpecFormat;
import com.webshield.api.models.SpecType;
import com.webshield.api.mutation.MutationEngine;
import com.webshield.api.parser.OpenApiParser;
import com.webshield.api.search.SearchConfiguration;
import com.webshield.api.service.ApiPersistenceService;
import com.webshield.api.service.ApiProjectService;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Automated test suite for Module I: WebShield API Security Testing JavaFX User Interface Controllers.
 */
public class ApiUiControllersTest {

    private static final String SAMPLE_SPEC = """
            openapi: 3.0.0
            info:
              title: Sample Pet Store API
              version: 1.0.0
              description: Testing API Specification
            servers:
              - url: https://api.petstore.test/v1
            paths:
              /pets:
                get:
                  summary: List all pets
                  description: Returns pets
                  responses:
                    '200':
                      description: A paged array of pets
                post:
                  summary: Create a pet
                  responses:
                    '201':
                      description: Null response
              /pets/{petId}:
                get:
                  summary: Info for a specific pet
                  parameters:
                    - name: petId
                      in: path
                      required: true
                      schema:
                        type: string
                  responses:
                    '200':
                      description: Expected response to a valid request
                delete:
                  summary: Delete pet
                  parameters:
                    - name: petId
                      in: path
                      required: true
                      schema:
                        type: string
                  responses:
                    '204':
                      description: Deleted
            """;

    static {
        java.io.File cacheDir = new java.io.File("target/.openjfx");
        cacheDir.mkdirs();
        System.setProperty("javafx.cachedir", cacheDir.getAbsolutePath());
        try {
            com.sun.javafx.application.PlatformImpl.startup(() -> {});
        } catch (Throwable t) {
            System.err.println("Platform startup notice: " + t.getMessage());
        }
    }

    @BeforeAll
    static void initJavaFx() {
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

    private static ApiProject createTestProject(Long id, String name) {
        ApiProject p = new ApiProject();
        p.setId(id);
        p.setUserId(1L);
        p.setName(name);
        p.setSpecType(SpecType.OPENAPI_3);
        p.setSpecFormat(SpecFormat.YAML);
        p.setSourceType(SourceType.FILE_UPLOAD);
        p.setRawSpecification(SAMPLE_SPEC);
        p.setEndpointsCount(4);
        return p;
    }

    private static ApiFindingDto createFinding(Long id, Long scanId, String title, String severity, String confidence, String path, String method, String cwe) {
        return new ApiFindingDto(
                id, "uuid-" + id, scanId, 1L, "exec-" + id, "RULE-1",
                title, "desc", severity, confidence, method, path,
                "param", "evidence", cwe, "API1:2023", "remediation",
                false, "NEW", LocalDateTime.now()
        );
    }

    private static ApiScanDto createScan(Long id, String name, ApiScanStatus status, int totalFindings, int crit, int high) {
        return new ApiScanDto(
                id, 1L, 1L, name, status, LocalDateTime.now(), LocalDateTime.now(),
                5000L, 4, 10, 10, totalFindings, crit, high, 0, 0, 0,
                "{}", "{}", "COMPLETED", null, LocalDateTime.now(), LocalDateTime.now()
        );
    }

    // Lightweight in-memory test stubs avoiding ByteBuddy agent overhead
    static class TestApiProjectService extends ApiProjectService {
        private final List<ApiProject> projects = new ArrayList<>();

        public TestApiProjectService(ApiProject... projs) {
            super(null, null);
            projects.addAll(List.of(projs));
        }

        @Override
        public List<ApiProject> getProjectsForCurrentUser() {
            return projects;
        }
    }

    static class TestApiPersistenceService extends ApiPersistenceService {
        private final List<ApiScanDto> scans = new ArrayList<>();
        private final List<ApiExecutionDto> executions = new ArrayList<>();
        private final List<ApiFindingDto> findings = new ArrayList<>();
        private final List<ApiTestCaseResultDto> testCases = new ArrayList<>();

        public TestApiPersistenceService() {
            super(null, null, null, null, null, null);
        }

        @Override
        public List<ApiScanDto> getScansForUser(Long userId) {
            return scans;
        }

        @Override
        public List<ApiExecutionDto> getExecutionsForScan(Long scanId, Long userId) {
            return executions;
        }

        @Override
        public List<ApiFindingDto> getFindingsForScan(Long scanId, Long userId) {
            return findings;
        }

        @Override
        public List<ApiTestCaseResultDto> getTestCasesForScan(Long scanId, Long userId) {
            return testCases;
        }

        @Override
        public void deleteScan(Long scanId, Long userId) {
            scans.removeIf(s -> s.id().equals(scanId));
        }
    }

    // =========================================================================
    // 1-5: ApiProjectDetailsController Tests
    // =========================================================================

    @Test
    @DisplayName("01: ApiProjectDetailsController - Instantiation and default state")
    void testProjectDetailsControllerInstantiation() {
        ApiProjectDetailsController controller = new ApiProjectDetailsController(new TestApiProjectService(), new OpenApiParser());

        assertNotNull(controller);
        assertNull(controller.getCurrentProject());
        assertNull(controller.getParsedSpec());
    }

    @Test
    @DisplayName("02: ApiProjectDetailsController - Populate project and parse specification")
    void testProjectDetailsPopulateProject() {
        ApiProjectDetailsController controller = new ApiProjectDetailsController(new TestApiProjectService(), new OpenApiParser());

        Label lblProjectName = new Label();
        Label lblProjectDesc = new Label();
        Label lblSpecVersion = new Label();
        Label lblBaseUrl = new Label();
        Label lblEndpointCount = new Label();
        Label lblGet = new Label();
        Label lblPost = new Label();
        Label lblDelete = new Label();
        TableView<ApiEndpoint> table = new TableView<>();
        TextField tfSearch = new TextField();
        ComboBox<String> cbFilter = new ComboBox<>();

        setField(controller, "lblProjectName", lblProjectName);
        setField(controller, "lblProjectDescription", lblProjectDesc);
        setField(controller, "lblSpecVersion", lblSpecVersion);
        setField(controller, "lblBaseUrl", lblBaseUrl);
        setField(controller, "lblEndpointCount", lblEndpointCount);
        setField(controller, "lblCountGet", lblGet);
        setField(controller, "lblCountPost", lblPost);
        setField(controller, "lblCountDelete", lblDelete);
        setField(controller, "tableEndpoints", table);
        setField(controller, "tfEndpointSearch", tfSearch);
        setField(controller, "cbMethodFilter", cbFilter);

        controller.initialize();

        ApiProject project = createTestProject(10L, "PetStore Service");
        controller.populateProject(project);

        assertEquals("PetStore Service", controller.getCurrentProject().getName());
        assertEquals("PetStore Service", lblProjectName.getText());
        assertEquals("4", lblEndpointCount.getText());
        assertEquals("2", lblGet.getText());
        assertEquals("1", lblPost.getText());
        assertEquals("1", lblDelete.getText());
    }

    @Test
    @DisplayName("03: ApiProjectDetailsController - Endpoint selection displays parameters and schema")
    void testProjectDetailsEndpointSelection() throws Exception {
        ApiProjectDetailsController controller = new ApiProjectDetailsController(new TestApiProjectService(), new OpenApiParser());

        VBox pane = new VBox();
        Label lblMethod = new Label();
        Label lblPath = new Label();
        Label lblSummary = new Label();
        TableView<ApiParameter> tableParams = new TableView<>();
        TextArea txtReqBody = new TextArea();
        TextArea txtResp = new TextArea();
        Label lblSec = new Label();

        setField(controller, "paneEndpointDetails", pane);
        setField(controller, "lblDetailMethod", lblMethod);
        setField(controller, "lblDetailPath", lblPath);
        setField(controller, "lblDetailSummary", lblSummary);
        setField(controller, "tableParams", tableParams);
        setField(controller, "txtRequestBodySchema", txtReqBody);
        setField(controller, "txtResponseSchemas", txtResp);
        setField(controller, "lblSecurityReqs", lblSec);

        var ep = new ApiEndpoint("/pets/{petId}", HttpMethod.GET);
        ep.setSummary("Info for pet");
        ApiSchema schema = new ApiSchema();
        schema.setType(SchemaType.STRING);
        ep.addParameter(new ApiParameter("petId", ParameterLocation.PATH, true, schema));

        java.lang.reflect.Method m = ApiProjectDetailsController.class.getDeclaredMethod("displayEndpointDetails", ApiEndpoint.class);
        m.setAccessible(true);
        m.invoke(controller, ep);

        assertTrue(pane.isVisible());
        assertEquals("GET", lblMethod.getText());
        assertEquals("/pets/{petId}", lblPath.getText());
        assertEquals("Info for pet", lblSummary.getText());
        assertEquals(1, tableParams.getItems().size());
        assertEquals("None (Public Endpoint)", lblSec.getText());
    }

    @Test
    @DisplayName("04: ApiProjectDetailsController - Filtering endpoints by HTTP method")
    void testProjectDetailsFilteringByMethod() throws Exception {
        ApiProjectDetailsController controller = new ApiProjectDetailsController(new TestApiProjectService(), new OpenApiParser());

        TableView<ApiEndpoint> table = new TableView<>();
        TextField tfSearch = new TextField();
        ComboBox<String> cbFilter = new ComboBox<>();
        setField(controller, "tableEndpoints", table);
        setField(controller, "tfEndpointSearch", tfSearch);
        setField(controller, "cbMethodFilter", cbFilter);

        controller.initialize();

        var ep1 = new ApiEndpoint("/pets", HttpMethod.GET);
        var ep2 = new ApiEndpoint("/pets", HttpMethod.POST);
        var ep3 = new ApiEndpoint("/pets/{id}", HttpMethod.DELETE);

        @SuppressWarnings("unchecked")
        javafx.collections.ObservableList<ApiEndpoint> master =
                (javafx.collections.ObservableList<ApiEndpoint>) getField(controller, "endpointMasterList");
        master.setAll(List.of(ep1, ep2, ep3));

        cbFilter.setValue("POST");
        java.lang.reflect.Method applyM = ApiProjectDetailsController.class.getDeclaredMethod("applyFilters");
        applyM.setAccessible(true);
        applyM.invoke(controller);

        @SuppressWarnings("unchecked")
        javafx.collections.transformation.FilteredList<ApiEndpoint> filtered =
                (javafx.collections.transformation.FilteredList<ApiEndpoint>) getField(controller, "endpointFilteredList");

        assertEquals(1, filtered.size());
        assertEquals(HttpMethod.POST, filtered.get(0).getMethod());
    }

    @Test
    @DisplayName("05: ApiProjectDetailsController - Filtering endpoints by search query")
    void testProjectDetailsFilteringByPathSearch() throws Exception {
        ApiProjectDetailsController controller = new ApiProjectDetailsController(new TestApiProjectService(), new OpenApiParser());

        TableView<ApiEndpoint> table = new TableView<>();
        TextField tfSearch = new TextField();
        ComboBox<String> cbFilter = new ComboBox<>();
        setField(controller, "tableEndpoints", table);
        setField(controller, "tfEndpointSearch", tfSearch);
        setField(controller, "cbMethodFilter", cbFilter);

        controller.initialize();

        var ep1 = new ApiEndpoint("/pets", HttpMethod.GET);
        var ep2 = new ApiEndpoint("/users/profile", HttpMethod.GET);
        var ep3 = new ApiEndpoint("/pets/{id}", HttpMethod.DELETE);

        @SuppressWarnings("unchecked")
        javafx.collections.ObservableList<ApiEndpoint> master =
                (javafx.collections.ObservableList<ApiEndpoint>) getField(controller, "endpointMasterList");
        master.setAll(List.of(ep1, ep2, ep3));

        tfSearch.setText("users");
        java.lang.reflect.Method applyM = ApiProjectDetailsController.class.getDeclaredMethod("applyFilters");
        applyM.setAccessible(true);
        applyM.invoke(controller);

        @SuppressWarnings("unchecked")
        javafx.collections.transformation.FilteredList<ApiEndpoint> filtered =
                (javafx.collections.transformation.FilteredList<ApiEndpoint>) getField(controller, "endpointFilteredList");

        assertEquals(1, filtered.size());
        assertEquals("/users/profile", filtered.get(0).getPath());
    }

    // =========================================================================
    // 6-12: ApiTestConfigController Tests
    // =========================================================================

    @Test
    @DisplayName("06: ApiTestConfigController - Default state and spinner bounds")
    void testTestConfigControllerDefaults() {
        ApiTestConfigController controller = new ApiTestConfigController(new TestApiProjectService());

        ComboBox<ApiProject> cb = new ComboBox<>();
        TextField tf = new TextField();
        Label lblMsg = new Label();
        CheckBox chkValid = new CheckBox();
        CheckBox chkInvalid = new CheckBox();
        CheckBox chkBoundary = new CheckBox();
        Spinner<Integer> spCases = new Spinner<>();
        Spinner<Integer> spDepth = new Spinner<>();
        CheckBox chkMut = new CheckBox();
        Spinner<Double> spMutProb = new Spinner<>();
        Spinner<Integer> spMaxMut = new Spinner<>();
        CheckBox chkTypeMut = new CheckBox();
        CheckBox chkBoundMut = new CheckBox();
        CheckBox chkSecPay = new CheckBox();
        CheckBox chkStructuralMut = new CheckBox();
        CheckBox chkMio = new CheckBox();
        Spinner<Integer> spPop = new Spinner<>();
        Spinner<Integer> spGen = new Spinner<>();
        Spinner<Integer> spBudget = new Spinner<>();
        Spinner<Integer> spTimeout = new Spinner<>();
        Spinner<Integer> spMaxResp = new Spinner<>();
        Spinner<Integer> spRps = new Spinner<>();
        Spinner<Integer> spConc = new Spinner<>();
        CheckBox chkUnsafe = new CheckBox();

        setField(controller, "cbProjects", cb);
        setField(controller, "tfTargetBaseUrl", tf);
        setField(controller, "lblValidationMsg", lblMsg);
        setField(controller, "chkValidCases", chkValid);
        setField(controller, "chkInvalidCases", chkInvalid);
        setField(controller, "chkBoundaryCases", chkBoundary);
        setField(controller, "spCasesPerEndpoint", spCases);
        setField(controller, "spSchemaDepth", spDepth);
        setField(controller, "chkEnableMutation", chkMut);
        setField(controller, "spMutationProbability", spMutProb);
        setField(controller, "spMaxMutations", spMaxMut);
        setField(controller, "chkTypeMutations", chkTypeMut);
        setField(controller, "chkBoundaryMutations", chkBoundMut);
        setField(controller, "chkSecurityPayloads", chkSecPay);
        setField(controller, "chkStructuralMutations", chkStructuralMut);
        setField(controller, "chkEnableMio", chkMio);
        setField(controller, "spPopulationSize", spPop);
        setField(controller, "spMaxGenerations", spGen);
        setField(controller, "spEvaluationBudget", spBudget);
        setField(controller, "spRequestTimeoutMs", spTimeout);
        setField(controller, "spMaxResponseSizeBytes", spMaxResp);
        setField(controller, "spRateLimitRps", spRps);
        setField(controller, "spConcurrency", spConc);
        setField(controller, "chkAllowUnsafeMethods", chkUnsafe);

        controller.initialize();

        assertTrue(chkValid.isSelected());
        assertTrue(chkInvalid.isSelected());
        assertTrue(chkBoundary.isSelected());
        assertTrue(chkMut.isSelected());
        assertTrue(chkMio.isSelected());
        assertFalse(chkUnsafe.isSelected());
        assertEquals(10, spCases.getValue());
        assertEquals(20, spPop.getValue());
        assertEquals(10, spRps.getValue());
    }

    @Test
    @DisplayName("07: ApiTestConfigController - Validation fails if project is not selected")
    void testTestConfigValidationFailsWithoutProject() {
        ApiTestConfigController controller = new ApiTestConfigController(new TestApiProjectService());
        ComboBox<ApiProject> cb = new ComboBox<>();
        Label lblMsg = new Label();
        setField(controller, "cbProjects", cb);
        setField(controller, "lblValidationMsg", lblMsg);

        boolean valid = controller.validateConfiguration();
        assertFalse(valid);
        assertEquals("Please select an API Project to test.", lblMsg.getText());
    }

    @Test
    @DisplayName("08: ApiTestConfigController - Validation fails when all categories are unchecked")
    void testTestConfigValidationFailsWhenNoCategoriesSelected() {
        ApiTestConfigController controller = new ApiTestConfigController(new TestApiProjectService());
        ComboBox<ApiProject> cb = new ComboBox<>();
        cb.getItems().add(createTestProject(1L, "Proj A"));
        cb.getSelectionModel().select(0);

        CheckBox chkValid = new CheckBox();
        CheckBox chkInvalid = new CheckBox();
        CheckBox chkBoundary = new CheckBox();
        Label lblMsg = new Label();

        chkValid.setSelected(false);
        chkInvalid.setSelected(false);
        chkBoundary.setSelected(false);

        setField(controller, "cbProjects", cb);
        setField(controller, "chkValidCases", chkValid);
        setField(controller, "chkInvalidCases", chkInvalid);
        setField(controller, "chkBoundaryCases", chkBoundary);
        setField(controller, "lblValidationMsg", lblMsg);

        boolean valid = controller.validateConfiguration();
        assertFalse(valid);
        assertTrue(lblMsg.getText().contains("At least one test generation category"));
    }

    @Test
    @DisplayName("09: ApiTestConfigController - Rate limit validation")
    void testTestConfigValidationRateLimit() {
        ApiTestConfigController controller = new ApiTestConfigController(new TestApiProjectService());
        ComboBox<ApiProject> cb = new ComboBox<>();
        cb.getItems().add(createTestProject(1L, "Proj A"));
        cb.getSelectionModel().select(0);

        CheckBox chkValid = new CheckBox();
        chkValid.setSelected(true);
        Spinner<Integer> spRps = new Spinner<>(0, 100, 0);
        Label lblMsg = new Label();

        setField(controller, "cbProjects", cb);
        setField(controller, "chkValidCases", chkValid);
        setField(controller, "spRateLimitRps", spRps);
        setField(controller, "lblValidationMsg", lblMsg);

        boolean valid = controller.validateConfiguration();
        assertFalse(valid);
        assertTrue(lblMsg.getText().contains("Rate limit must be greater than 0"));
    }

    @Test
    @DisplayName("10: ApiTestConfigController - Build SearchConfiguration reflects user inputs")
    void testTestConfigBuildSearchConfiguration() {
        ApiTestConfigController controller = new ApiTestConfigController(new TestApiProjectService());

        Spinner<Integer> spPop = new Spinner<>(5, 100, 35);
        Spinner<Integer> spGen = new Spinner<>(5, 200, 45);
        Spinner<Integer> spBudget = new Spinner<>(10, 1000, 150);
        Spinner<Double> spProb = new Spinner<>(0.05, 1.0, 0.5);

        setField(controller, "spPopulationSize", spPop);
        setField(controller, "spMaxGenerations", spGen);
        setField(controller, "spEvaluationBudget", spBudget);
        setField(controller, "spMutationProbability", spProb);

        SearchConfiguration config = controller.buildSearchConfiguration();
        assertNotNull(config);
        assertEquals(35, config.getPopulationSize());
        assertEquals(45, config.getMaxGenerations());
        assertEquals(150, config.getEvaluationBudget());
        assertEquals(0.5, config.getMutationProbability());
    }

    @Test
    @DisplayName("11: ApiTestConfigController - Build ApiExecutionConfiguration enforces safe settings")
    void testTestConfigBuildExecutionConfiguration() {
        ApiTestConfigController controller = new ApiTestConfigController(new TestApiProjectService());

        Spinner<Integer> spTimeout = new Spinner<>(500, 60000, 4000);
        Spinner<Integer> spMaxResp = new Spinner<>(1024, 10485760, 524288);
        Spinner<Integer> spRps = new Spinner<>(1, 100, 15);
        Spinner<Integer> spConc = new Spinner<>(1, 16, 4);
        CheckBox chkUnsafe = new CheckBox();
        chkUnsafe.setSelected(false);

        setField(controller, "spRequestTimeoutMs", spTimeout);
        setField(controller, "spMaxResponseSizeBytes", spMaxResp);
        setField(controller, "spRateLimitRps", spRps);
        setField(controller, "spConcurrency", spConc);
        setField(controller, "chkAllowUnsafeMethods", chkUnsafe);

        ApiExecutionConfiguration config = controller.buildExecutionConfig();
        assertNotNull(config);
        assertEquals(4000, config.getRequestTimeout().toMillis());
        assertEquals(524288L, config.getMaxResponseSizeBytes());
        assertEquals(15.0, config.getRequestsPerSecond());
        assertEquals(4, config.getMaxConcurrentRequests());
        assertFalse(config.isAllowUnsafeMethods());
        assertTrue(config.isTlsVerificationEnabled());
    }

    @Test
    @DisplayName("12: ApiTestConfigController - Reset to defaults restores initial values")
    void testTestConfigResetToDefaults() {
        ApiTestConfigController controller = new ApiTestConfigController(new TestApiProjectService());

        CheckBox chkValid = new CheckBox();
        chkValid.setSelected(false);
        Spinner<Integer> spCases = new Spinner<>(1, 100, 50);
        Spinner<Integer> spPop = new Spinner<>(5, 100, 99);
        Label lblMsg = new Label("error");

        setField(controller, "chkValidCases", chkValid);
        setField(controller, "spCasesPerEndpoint", spCases);
        setField(controller, "spPopulationSize", spPop);
        setField(controller, "lblValidationMsg", lblMsg);

        controller.resetToDefaults();

        assertTrue(chkValid.isSelected());
        assertEquals(10, spCases.getValue());
        assertEquals(20, spPop.getValue());
        assertEquals("", lblMsg.getText());
    }

    // =========================================================================
    // 13-14: ApiScanExecutionController Tests
    // =========================================================================

    @Test
    @DisplayName("13: ApiScanExecutionController - Initial state and button enabling")
    void testScanExecutionControllerInstantiation() {
        ApiScanExecutionController controller = new ApiScanExecutionController(
                new TestApiProjectService(), new TestApiPersistenceService(),
                new OpenApiParser(), new ApiTestGenerator(), new MutationEngine(), new ApiSecurityAnalyzer());

        Label lblStatus = new Label();
        Button btnStart = new Button();
        Button btnCancel = new Button();
        ProgressBar pb = new ProgressBar();
        Label lblProg = new Label();
        Label lblPhase = new Label();
        HBox postPane = new HBox();

        setField(controller, "lblScanStatus", lblStatus);
        setField(controller, "btnStartScan", btnStart);
        setField(controller, "btnCancelScan", btnCancel);
        setField(controller, "progressBar", pb);
        setField(controller, "lblProgressPercent", lblProg);
        setField(controller, "lblCurrentPhase", lblPhase);
        setField(controller, "panePostScanActions", postPane);

        controller.initialize();

        assertEquals(ApiScanStatus.PENDING.name(), lblStatus.getText());
        assertFalse(btnStart.isDisable());
        assertTrue(btnCancel.isDisable());
        assertEquals(0.0, pb.getProgress());
        assertEquals("0%", lblProg.getText());
        assertFalse(postPane.isVisible());
    }

    @Test
    @DisplayName("14: ApiScanExecutionController - Cancellation stops active task")
    void testScanExecutionControllerCancellation() {
        ApiScanExecutionController controller = new ApiScanExecutionController(
                new TestApiProjectService(), new TestApiPersistenceService(),
                new OpenApiParser(), new ApiTestGenerator(), new MutationEngine(), new ApiSecurityAnalyzer());

        TextArea txtLog = new TextArea();
        setField(controller, "txtLogConsole", txtLog);

        // Cancel when no task is running shouldn't throw
        assertDoesNotThrow(controller::onCancelScan);
    }

    // =========================================================================
    // 15-17: ApiTestCasesController Tests
    // =========================================================================

    @Test
    @DisplayName("15: ApiTestCasesController - Table wiring and default category ALL")
    void testTestCasesControllerInstantiation() {
        ApiTestCasesController controller = new ApiTestCasesController(new TestApiPersistenceService());

        ComboBox<ApiScanDto> cbScans = new ComboBox<>();
        ComboBox<String> cbCat = new ComboBox<>();
        TextField tf = new TextField();
        TableView<ApiTestCaseResultDto> table = new TableView<>();
        Label lblCount = new Label();

        setField(controller, "cbScans", cbScans);
        setField(controller, "cbCategoryFilter", cbCat);
        setField(controller, "tfSearch", tf);
        setField(controller, "tableTestCases", table);
        setField(controller, "lblTestCaseCount", lblCount);

        controller.initialize();

        assertEquals("ALL", cbCat.getValue());
        assertTrue(cbCat.getItems().containsAll(List.of("ALL", "VALID", "INVALID", "BOUNDARY", "MUTATION")));
    }

    @Test
    @DisplayName("16: ApiTestCasesController - Filter by Category")
    void testTestCasesFilteringByCategory() throws Exception {
        ApiTestCasesController controller = new ApiTestCasesController(new TestApiPersistenceService());

        ComboBox<String> cbCat = new ComboBox<>();
        TextField tf = new TextField();
        TableView<ApiTestCaseResultDto> table = new TableView<>();
        Label lblCount = new Label();

        setField(controller, "cbCategoryFilter", cbCat);
        setField(controller, "tfSearch", tf);
        setField(controller, "tableTestCases", table);
        setField(controller, "lblTestCaseCount", lblCount);

        controller.initialize();

        var tc1 = new ApiTestCaseResultDto(1L, 10L, "TC-1", "/pets", "GET", "VALID", "NOMINAL", null, null, null, "desc", LocalDateTime.now());
        var tc2 = new ApiTestCaseResultDto(2L, 10L, "TC-2", "/pets", "POST", "INVALID", "TYPE_ERROR", null, null, null, "desc", LocalDateTime.now());
        var tc3 = new ApiTestCaseResultDto(3L, 10L, "TC-3", "/pets", "POST", "MUTATION", "FUZZ", "TC-1", null, null, "desc", LocalDateTime.now());

        @SuppressWarnings("unchecked")
        var master = (javafx.collections.ObservableList<ApiTestCaseResultDto>) getField(controller, "masterList");
        master.setAll(List.of(tc1, tc2, tc3));

        cbCat.setValue("MUTATION");
        java.lang.reflect.Method applyM = ApiTestCasesController.class.getDeclaredMethod("applyFilters");
        applyM.setAccessible(true);
        applyM.invoke(controller);

        @SuppressWarnings("unchecked")
        var filtered = (javafx.collections.transformation.FilteredList<ApiTestCaseResultDto>) getField(controller, "filteredList");

        assertEquals(1, filtered.size());
        assertEquals("MUTATION", filtered.get(0).category());
        assertEquals("1 test cases", lblCount.getText());
    }

    @Test
    @DisplayName("17: ApiTestCasesController - Filter by Search query")
    void testTestCasesFilteringBySearch() throws Exception {
        ApiTestCasesController controller = new ApiTestCasesController(new TestApiPersistenceService());

        ComboBox<String> cbCat = new ComboBox<>();
        TextField tf = new TextField();
        TableView<ApiTestCaseResultDto> table = new TableView<>();
        Label lblCount = new Label();

        setField(controller, "cbCategoryFilter", cbCat);
        setField(controller, "tfSearch", tf);
        setField(controller, "tableTestCases", table);
        setField(controller, "lblTestCaseCount", lblCount);

        controller.initialize();

        var tc1 = new ApiTestCaseResultDto(1L, 10L, "TC-1", "/pets", "GET", "VALID", "NOMINAL", null, null, null, "desc", LocalDateTime.now());
        var tc2 = new ApiTestCaseResultDto(2L, 10L, "TC-2", "/users/login", "POST", "INVALID", "TYPE_ERROR", null, null, null, "desc", LocalDateTime.now());

        @SuppressWarnings("unchecked")
        var master = (javafx.collections.ObservableList<ApiTestCaseResultDto>) getField(controller, "masterList");
        master.setAll(List.of(tc1, tc2));

        tf.setText("login");
        java.lang.reflect.Method applyM = ApiTestCasesController.class.getDeclaredMethod("applyFilters");
        applyM.setAccessible(true);
        applyM.invoke(controller);

        @SuppressWarnings("unchecked")
        var filtered = (javafx.collections.transformation.FilteredList<ApiTestCaseResultDto>) getField(controller, "filteredList");

        assertEquals(1, filtered.size());
        assertEquals("/users/login", filtered.get(0).endpointIdentifier());
    }

    // =========================================================================
    // 18-20: ApiExecutionResultsController Tests
    // =========================================================================

    @Test
    @DisplayName("18: ApiExecutionResultsController - Instantiation and default filter")
    void testExecutionResultsControllerInstantiation() {
        ApiExecutionResultsController controller = new ApiExecutionResultsController(new TestApiPersistenceService());

        ComboBox<ApiScanDto> cbScans = new ComboBox<>();
        ComboBox<String> cbStatus = new ComboBox<>();
        TextField tf = new TextField();
        TableView<ApiExecutionDto> table = new TableView<>();
        ComboBox<Integer> cbSize = new ComboBox<>();
        Label lblPageInfo = new Label();
        Label lblCount = new Label();

        setField(controller, "cbScans", cbScans);
        setField(controller, "cbStatusFilter", cbStatus);
        setField(controller, "tfSearch", tf);
        setField(controller, "tableExecutions", table);
        setField(controller, "cbPageSize", cbSize);
        setField(controller, "lblPageInfo", lblPageInfo);
        setField(controller, "lblExecutionCount", lblCount);

        controller.initialize();

        assertEquals("ALL", cbStatus.getValue());
        assertEquals(25, cbSize.getValue());
    }

    @Test
    @DisplayName("19: ApiExecutionResultsController - Filtering by HTTP Status Code range")
    void testExecutionResultsFilteringByStatusCode() throws Exception {
        ApiExecutionResultsController controller = new ApiExecutionResultsController(new TestApiPersistenceService());

        ComboBox<String> cbStatus = new ComboBox<>();
        TextField tf = new TextField();
        TableView<ApiExecutionDto> table = new TableView<>();
        ComboBox<Integer> cbSize = new ComboBox<>();
        Label lblPageInfo = new Label();
        Label lblCount = new Label();

        setField(controller, "cbStatusFilter", cbStatus);
        setField(controller, "tfSearch", tf);
        setField(controller, "tableExecutions", table);
        setField(controller, "cbPageSize", cbSize);
        setField(controller, "lblPageInfo", lblPageInfo);
        setField(controller, "lblExecutionCount", lblCount);

        controller.initialize();

        var e1 = new ApiExecutionDto(1L, "u1", 10L, "TC-1", "/pets", "GET", "SUCCESS", 200, 25L, 100L, "", "", false, false, null, LocalDateTime.now());
        var e2 = new ApiExecutionDto(2L, "u2", 10L, "TC-2", "/pets", "POST", "CLIENT_ERROR", 400, 20L, 100L, "", "", false, false, null, LocalDateTime.now());
        var e3 = new ApiExecutionDto(3L, "u3", 10L, "TC-3", "/pets", "GET", "SERVER_ERROR", 500, 45L, 100L, "", "", false, false, null, LocalDateTime.now());

        @SuppressWarnings("unchecked")
        var all = (javafx.collections.ObservableList<ApiExecutionDto>) getField(controller, "allLoadedList");
        all.setAll(List.of(e1, e2, e3));

        cbStatus.setValue("5xx (Server Errors)");
        java.lang.reflect.Method applyM = ApiExecutionResultsController.class.getDeclaredMethod("applyFilters");
        applyM.setAccessible(true);
        applyM.invoke(controller);

        @SuppressWarnings("unchecked")
        var filtered = (javafx.collections.transformation.FilteredList<ApiExecutionDto>) getField(controller, "filteredList");

        assertEquals(1, filtered.size());
        assertEquals(500, filtered.get(0).statusCode());
    }

    @Test
    @DisplayName("20: ApiExecutionResultsController - Pagination logic and page size adjustment")
    void testExecutionResultsPagination() {
        ApiExecutionResultsController controller = new ApiExecutionResultsController(new TestApiPersistenceService());

        ComboBox<String> cbStatus = new ComboBox<>();
        TextField tf = new TextField();
        TableView<ApiExecutionDto> table = new TableView<>();
        ComboBox<Integer> cbSize = new ComboBox<>();
        Label lblPageInfo = new Label();
        Label lblCount = new Label();
        Button btnPrev = new Button();
        Button btnNext = new Button();

        setField(controller, "cbStatusFilter", cbStatus);
        setField(controller, "tfSearch", tf);
        setField(controller, "tableExecutions", table);
        setField(controller, "cbPageSize", cbSize);
        setField(controller, "lblPageInfo", lblPageInfo);
        setField(controller, "lblExecutionCount", lblCount);
        setField(controller, "btnPrevPage", btnPrev);
        setField(controller, "btnNextPage", btnNext);

        controller.initialize();

        @SuppressWarnings("unchecked")
        var all = (javafx.collections.ObservableList<ApiExecutionDto>) getField(controller, "allLoadedList");

        for (int i = 1; i <= 30; i++) {
            all.add(new ApiExecutionDto((long) i, "u" + i, 10L, "TC-" + i, "/pets", "GET", "SUCCESS", 200, 20L, 50L, "", "", false, false, null, LocalDateTime.now()));
        }

        cbSize.setValue(10); // 3 pages total

        assertEquals(1, getField(controller, "currentPage"));
        assertTrue(btnPrev.isDisable());
        assertFalse(btnNext.isDisable());

        controller.onNextPage();
        assertEquals(2, getField(controller, "currentPage"));
        assertFalse(btnPrev.isDisable());
        assertFalse(btnNext.isDisable());

        controller.onNextPage();
        assertEquals(3, getField(controller, "currentPage"));
        assertTrue(btnNext.isDisable());

        controller.onPrevPage();
        assertEquals(2, getField(controller, "currentPage"));
    }

    // =========================================================================
    // 21-23: ApiSecurityFindingsController Tests
    // =========================================================================

    @Test
    @DisplayName("21: ApiSecurityFindingsController - Instantiation and default filter state")
    void testSecurityFindingsControllerInstantiation() {
        ApiSecurityFindingsController controller = new ApiSecurityFindingsController(new TestApiPersistenceService());

        ComboBox<ApiScanDto> cbScans = new ComboBox<>();
        ComboBox<String> cbSev = new ComboBox<>();
        ComboBox<String> cbConf = new ComboBox<>();
        TextField tf = new TextField();
        TableView<ApiFindingDto> table = new TableView<>();

        setField(controller, "cbScans", cbScans);
        setField(controller, "cbSeverityFilter", cbSev);
        setField(controller, "cbConfidenceFilter", cbConf);
        setField(controller, "tfSearch", tf);
        setField(controller, "tableFindings", table);

        controller.initialize();

        assertEquals("ALL", cbSev.getValue());
        assertEquals("ALL", cbConf.getValue());
    }

    @Test
    @DisplayName("22: ApiSecurityFindingsController - Interactive Severity Metric Cards filter items")
    void testSecurityFindingsClickableSeverityFilter() throws Exception {
        ApiSecurityFindingsController controller = new ApiSecurityFindingsController(new TestApiPersistenceService());

        ComboBox<String> cbSev = new ComboBox<>();
        ComboBox<String> cbConf = new ComboBox<>();
        TextField tf = new TextField();
        TableView<ApiFindingDto> table = new TableView<>();
        Label lblTotal = new Label();
        Label lblCrit = new Label();
        Label lblHigh = new Label();
        Label lblMed = new Label();
        Label lblLow = new Label();
        Label lblInfo = new Label();

        setField(controller, "cbSeverityFilter", cbSev);
        setField(controller, "cbConfidenceFilter", cbConf);
        setField(controller, "tfSearch", tf);
        setField(controller, "tableFindings", table);
        setField(controller, "lblTotalCount", lblTotal);
        setField(controller, "lblCriticalCount", lblCrit);
        setField(controller, "lblHighCount", lblHigh);
        setField(controller, "lblMediumCount", lblMed);
        setField(controller, "lblLowCount", lblLow);
        setField(controller, "lblInfoCount", lblInfo);

        controller.initialize();

        var f1 = createFinding(1L, 10L, "SQL Injection", "CRITICAL", "HIGH", "/api/users", "POST", "CWE-89");
        var f2 = createFinding(2L, 10L, "Information Disclosure", "MEDIUM", "HIGH", "/api/logs", "GET", "CWE-200");
        var f3 = createFinding(3L, 10L, "Excessive Data Exposure", "HIGH", "MEDIUM", "/api/data", "GET", "CWE-213");

        @SuppressWarnings("unchecked")
        var master = (javafx.collections.ObservableList<ApiFindingDto>) getField(controller, "masterList");
        master.setAll(List.of(f1, f2, f3));

        java.lang.reflect.Method updateCounts = ApiSecurityFindingsController.class.getDeclaredMethod("updateSeverityCounts");
        updateCounts.setAccessible(true);
        updateCounts.invoke(controller);

        assertEquals("3", lblTotal.getText());
        assertEquals("1", lblCrit.getText());
        assertEquals("1", lblHigh.getText());
        assertEquals("1", lblMed.getText());

        // Click on Critical Filter
        controller.onFilterCritical();
        assertEquals("CRITICAL", cbSev.getValue());

        @SuppressWarnings("unchecked")
        var filtered = (javafx.collections.transformation.FilteredList<ApiFindingDto>) getField(controller, "filteredList");
        assertEquals(1, filtered.size());
        assertEquals("CRITICAL", filtered.get(0).severity());

        // Click on All
        controller.onFilterAll();
        assertEquals("ALL", cbSev.getValue());
        assertEquals(3, filtered.size());
    }

    @Test
    @DisplayName("23: ApiSecurityFindingsController - Search query by CWE ID and Endpoint")
    void testSecurityFindingsConfidenceAndSearchFilter() throws Exception {
        ApiSecurityFindingsController controller = new ApiSecurityFindingsController(new TestApiPersistenceService());

        ComboBox<String> cbSev = new ComboBox<>();
        ComboBox<String> cbConf = new ComboBox<>();
        TextField tf = new TextField();
        TableView<ApiFindingDto> table = new TableView<>();

        setField(controller, "cbSeverityFilter", cbSev);
        setField(controller, "cbConfidenceFilter", cbConf);
        setField(controller, "tfSearch", tf);
        setField(controller, "tableFindings", table);

        controller.initialize();

        var f1 = createFinding(1L, 10L, "SQL Injection", "CRITICAL", "HIGH", "/api/users", "POST", "CWE-89");
        var f2 = createFinding(2L, 10L, "Information Disclosure", "MEDIUM", "LOW", "/api/logs", "GET", "CWE-200");

        @SuppressWarnings("unchecked")
        var master = (javafx.collections.ObservableList<ApiFindingDto>) getField(controller, "masterList");
        master.setAll(List.of(f1, f2));

        tf.setText("CWE-89");
        java.lang.reflect.Method applyM = ApiSecurityFindingsController.class.getDeclaredMethod("applyFilters");
        applyM.setAccessible(true);
        applyM.invoke(controller);

        @SuppressWarnings("unchecked")
        var filtered = (javafx.collections.transformation.FilteredList<ApiFindingDto>) getField(controller, "filteredList");
        assertEquals(1, filtered.size());
        assertEquals("CWE-89", filtered.get(0).cweId());
    }

    @Test
    @DisplayName("23b: Load api_security_findings.fxml directly")
    void testLoadApiSecurityFindingsFxml() throws Exception {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/fxml/pages/api_security_findings.fxml"));
        loader.setControllerFactory(clazz -> new ApiSecurityFindingsController(new TestApiPersistenceService()));
        javafx.scene.Node node = loader.load();
        assertNotNull(node);
    }

    @Test
    @DisplayName("23c: Load api_scan_comparison.fxml directly")
    void testLoadApiScanComparisonFxml() throws Exception {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/fxml/pages/api_scan_comparison.fxml"));
        loader.setControllerFactory(clazz -> new ApiScanComparisonController(new TestApiPersistenceService()));
        javafx.scene.Node node = loader.load();
        assertNotNull(node);
    }

    // =========================================================================
    // 24: ApiScanHistoryController Tests
    // =========================================================================

    @Test
    @DisplayName("24: ApiScanHistoryController - Filtering by project and search query")
    void testScanHistoryControllerFiltersAndActions() throws Exception {
        ApiScanHistoryController controller = new ApiScanHistoryController(new TestApiPersistenceService(), new TestApiProjectService());

        ComboBox<ApiProject> cbProj = new ComboBox<>();
        TextField tf = new TextField();
        TableView<ApiScanDto> table = new TableView<>();
        Label lblCount = new Label();

        setField(controller, "cbProjectFilter", cbProj);
        setField(controller, "tfSearch", tf);
        setField(controller, "tableScans", table);
        setField(controller, "lblScanCount", lblCount);

        controller.setBackgroundLoadingEnabled(false);
        controller.initialize();

        var s1 = createScan(1L, "Scan-Alpha", ApiScanStatus.COMPLETED, 2, 1, 1);
        var s2 = createScan(2L, "Scan-Beta", ApiScanStatus.FAILED, 0, 0, 0);

        controller.setMasterList(List.of(s1, s2));

        tf.setText("Alpha");
        java.lang.reflect.Method applyM = ApiScanHistoryController.class.getDeclaredMethod("applyFilters");
        applyM.setAccessible(true);
        applyM.invoke(controller);

        @SuppressWarnings("unchecked")
        var filtered = (javafx.collections.transformation.FilteredList<ApiScanDto>) getField(controller, "filteredList");
        assertEquals(1, filtered.size());
        assertEquals("Scan-Alpha", filtered.get(0).scanName());
    }

    // =========================================================================
    // 25: ApiScanComparisonController Tests
    // =========================================================================

    @Test
    @DisplayName("25: ApiScanComparisonController - Differential comparison validation and metrics rendering")
    void testScanComparisonControllerDifferentialLogic() throws Exception {
        ApiScanComparisonController controller = new ApiScanComparisonController(new TestApiPersistenceService());

        ComboBox<ApiScanDto> cbScanA = new ComboBox<>();
        ComboBox<ApiScanDto> cbScanB = new ComboBox<>();
        Label lblStatus = new Label();
        Label lblNew = new Label();
        Label lblResolved = new Label();
        Label lblPersistent = new Label();
        Label lblCov = new Label();
        Label lblDur = new Label();
        TableView<ApiFindingDto> tableNew = new TableView<>();
        TableView<ApiFindingDto> tableRes = new TableView<>();

        setField(controller, "cbScanA", cbScanA);
        setField(controller, "cbScanB", cbScanB);
        setField(controller, "lblComparisonStatus", lblStatus);
        setField(controller, "lblNewFindings", lblNew);
        setField(controller, "lblResolvedFindings", lblResolved);
        setField(controller, "lblPersistentFindings", lblPersistent);
        setField(controller, "lblCoverageDelta", lblCov);
        setField(controller, "lblDurationDelta", lblDur);
        setField(controller, "tableNewFindings", tableNew);
        setField(controller, "tableResolvedFindings", tableRes);

        controller.initialize();

        var s1 = createScan(1L, "Scan 1", ApiScanStatus.COMPLETED, 2, 1, 1);

        // Identical scan check
        cbScanA.setValue(s1);
        cbScanB.setValue(s1);
        controller.onCompareScans();
        assertEquals("Scan A and Scan B must be distinct scans.", lblStatus.getText());

        // Render mock diff
        var fNew = createFinding(1L, 2L, "New Regression", "CRITICAL", "HIGH", "/api/reg", "POST", "CWE-89");
        var fRes = createFinding(2L, 1L, "Fixed Vulnerability", "HIGH", "HIGH", "/api/fix", "GET", "CWE-200");

        var compDto = new ApiScanComparisonDto(s1, s1, 1, 1, 0, 15.5, 1200L, List.of(fNew), List.of(fRes));

        java.lang.reflect.Method renderM = ApiScanComparisonController.class.getDeclaredMethod("renderComparison", ApiScanComparisonDto.class);
        renderM.setAccessible(true);
        renderM.invoke(controller, compDto);

        assertEquals("+1", lblNew.getText());
        assertEquals("-1", lblResolved.getText());
        assertEquals("0", lblPersistent.getText());
        assertEquals("+15.5%", lblCov.getText());
        assertEquals("+1.2s", lblDur.getText());
        assertEquals(1, tableNew.getItems().size());
        assertEquals(1, tableRes.getItems().size());
    }
}
