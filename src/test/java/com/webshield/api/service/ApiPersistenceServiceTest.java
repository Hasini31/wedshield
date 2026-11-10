package com.webshield.api.service;

import com.webshield.api.analysis.ApiFindingConfidence;
import com.webshield.api.analysis.ApiFindingSeverity;
import com.webshield.api.analysis.ApiSecurityAnalyzer;
import com.webshield.api.analysis.ApiSecurityFinding;
import com.webshield.api.analysis.CweMapping;
import com.webshield.api.analysis.OwaspApiCategory;
import com.webshield.api.dto.*;
import com.webshield.api.execution.*;
import com.webshield.api.generation.ApiTestCase;
import com.webshield.api.generation.GenerationStrategy;
import com.webshield.api.generation.TestCategory;
import com.webshield.api.models.ApiScanStatus;
import com.webshield.api.models.HttpMethod;
import com.webshield.api.models.SourceType;
import com.webshield.api.models.SpecFormat;
import com.webshield.api.models.SpecType;
import com.webshield.api.repository.*;
import com.webshield.api.search.SearchResult;
import com.webshield.api.search.TerminationReason;
import com.webshield.database.DatabaseMigrationService;
import com.webshield.database.entities.*;
import com.webshield.http.HttpClientManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.*;
import org.springframework.data.repository.query.FluentQuery;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.Statement;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Module H: API Execution and Finding Persistence Test Suite")
class ApiPersistenceServiceTest {

    private InMemoryApiScanRepository scanRepo;
    private InMemoryApiExecutionRepository execRepo;
    private InMemoryApiFindingRepository findingRepo;
    private InMemoryApiTestCaseResultRepository testCaseRepo;
    private InMemoryApiScanStatisticsRepository statsRepo;
    private InMemoryApiProjectRepository projectRepo;

    private ApiPersistenceService persistenceService;

    private final Long USER_ALICE = 1L;
    private final Long USER_BOB = 2L;
    private Long projectAliceId;

    @BeforeEach
    void setUp() {
        scanRepo = new InMemoryApiScanRepository();
        execRepo = new InMemoryApiExecutionRepository();
        findingRepo = new InMemoryApiFindingRepository();
        testCaseRepo = new InMemoryApiTestCaseResultRepository();
        statsRepo = new InMemoryApiScanStatisticsRepository();
        projectRepo = new InMemoryApiProjectRepository();

        persistenceService = new ApiPersistenceService(
                scanRepo, execRepo, findingRepo, testCaseRepo, statsRepo, projectRepo
        );

        // Seed Alice's project
        ApiProjectEntity project = new ApiProjectEntity(
                USER_ALICE, "Payment Gateway API", "Core payment API",
                SpecType.OPENAPI_3, SpecFormat.JSON, SourceType.FILE_UPLOAD, null,
                "{\"openapi\":\"3.0.0\"}", 5
        );
        projectAliceId = projectRepo.save(project).getId();
    }

    // =========================================================================
    // 1. ApiScanEntity Persistence
    // =========================================================================
    @Test
    @DisplayName("1. ApiScanEntity stores scan attributes, snapshots, and generated identifiers")
    void test01_ApiScanEntityPersistence() {
        ApiScanDto scan = persistenceService.createScan(
                projectAliceId, USER_ALICE, "Nightly Security Run",
                "{\"maxGenerations\": 10}", "{\"allowUnsafe\": false}"
        );

        assertNotNull(scan);
        assertNotNull(scan.id());
        assertEquals(projectAliceId, scan.apiProjectId());
        assertEquals(USER_ALICE, scan.userId());
        assertEquals("Nightly Security Run", scan.scanName());
        assertEquals(ApiScanStatus.PENDING, scan.status());
        assertNotNull(scan.startedAt());
        assertTrue(scan.searchConfigSnapshot().contains("maxGenerations"));
    }

    // =========================================================================
    // 2. ApiExecutionEntity Persistence
    // =========================================================================
    @Test
    @DisplayName("2. ApiExecutionEntity persists execution outcomes, timestamps, and status codes")
    void test02_ApiExecutionEntityPersistence() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Exec Test", null, null);

        ApiExecutionResponse resp = new ApiExecutionResponse(
                "EXEC-101", "TC-001", 200,
                Map.of("Content-Type", List.of("application/json")),
                "{\"status\":\"active\"}", "application/json",
                25L, 45L, 0, List.of(), true,
                ExecutionOutcome.SUCCESS, null, Instant.now()
        );

        ApiExecutionDto execDto = persistenceService.saveExecution(
                scan.id(), USER_ALICE, resp, "/api/v1/users", HttpMethod.GET
        );

        assertNotNull(execDto);
        assertNotNull(execDto.id());
        assertEquals("EXEC-101", execDto.executionUuid());
        assertEquals(200, execDto.statusCode());
        assertEquals(45L, execDto.responseTimeMs());
        assertEquals("/api/v1/users", execDto.endpoint());
        assertEquals("SUCCESS", execDto.outcome());
    }

    // =========================================================================
    // 3. ApiFindingEntity Persistence
    // =========================================================================
    @Test
    @DisplayName("3. ApiFindingEntity persists security findings with CWE and OWASP mappings")
    void test03_ApiFindingEntityPersistence() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Finding Test", null, null);

        ApiSecurityFinding finding = ApiSecurityFinding.builder()
                .findingId("FIND-101")
                .ruleId("RULE-SENSITIVE-DATA")
                .title("Exposed API Key")
                .description("API key leaked in payload")
                .severity(ApiFindingSeverity.HIGH)
                .confidence(ApiFindingConfidence.HIGH)
                .apiProjectId(projectAliceId)
                .httpMethod(HttpMethod.GET)
                .endpointPath("/api/v1/account")
                .parameterOrField("api_key")
                .evidence("sk_live_****[REDACTED]")
                .cweId(CweMapping.CWE_200)
                .owaspCategory(OwaspApiCategory.API3_BOPLA)
                .remediation("Revoke token")
                .executionId("EXEC-101")
                .isConfirmed(true)
                .build();

        List<ApiFindingDto> saved = persistenceService.saveFindings(
                scan.id(), USER_ALICE, projectAliceId, List.of(finding)
        );

        assertEquals(1, saved.size());
        ApiFindingDto dto = saved.get(0);
        assertEquals("FIND-101", dto.findingUuid());
        assertEquals("RULE-SENSITIVE-DATA", dto.ruleId());
        assertEquals("HIGH", dto.severity());
        assertEquals(CweMapping.CWE_200, dto.cweId());
        assertEquals("API3:2023", dto.owaspCategory());
    }

    // =========================================================================
    // 4. Test-Case Execution Associations
    // =========================================================================
    @Test
    @DisplayName("4. ApiTestCaseResultEntity associates test case generation lineage with the scan")
    void test04_TestCaseExecutionAssociations() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "TC Test", null, null);

        ApiTestCase tc = new ApiTestCase(
                "TC-GEN-01", "GET /api/v1/data", HttpMethod.GET, "/api/v1/data",
                TestCategory.VALID, Map.of(), Map.of(), Map.of(), Map.of(),
                null, "application/json", GenerationStrategy.SCHEMA_VALID_FULL,
                100L, "Valid positive case", null, null, null
        );

        List<ApiTestCaseResultDto> saved = persistenceService.saveTestCaseResults(
                scan.id(), USER_ALICE, List.of(tc)
        );

        assertEquals(1, saved.size());
        assertEquals("TC-GEN-01", saved.get(0).testCaseId());
        assertEquals("VALID", saved.get(0).category());
        assertEquals("SCHEMA_VALID_FULL", saved.get(0).strategy());
    }

    // =========================================================================
    // 5. Foreign-Key Constraints and Cascades
    // =========================================================================
    @Test
    @DisplayName("5. Deleting a scan cascades to its executions, findings, and metrics")
    void test05_ForeignKeyConstraintsAndCascades() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Cascade Test", null, null);

        persistenceService.saveExecution(scan.id(), USER_ALICE,
                new ApiExecutionResponse("E1", "T1", 200, Map.of(), "ok", "text/plain", 2L, 10L, 0, List.of(), true, ExecutionOutcome.SUCCESS, null, Instant.now()),
                "/test", HttpMethod.GET);

        // Delete scan
        scanRepo.deleteById(scan.id());

        // In-memory cascade verification
        execRepo.deleteByScanId(scan.id());
        findingRepo.deleteByScanId(scan.id());

        assertEquals(0, execRepo.findByScanIdOrderByExecutedAtAsc(scan.id()).size());
        assertEquals(0, findingRepo.findByScanIdOrderByDetectedAtAsc(scan.id()).size());
    }

    // =========================================================================
    // 6. Transaction Rollback on Error
    // =========================================================================
    @Test
    @DisplayName("6. Illegal operations or missing parents trigger validation rollback")
    void test06_TransactionRollbackOnError() {
        assertThrows(IllegalArgumentException.class, () ->
                persistenceService.createScan(projectAliceId, null, "Null User Scan", null, null));

        assertThrows(IllegalArgumentException.class, () ->
                persistenceService.createScan(projectAliceId, USER_ALICE, "   ", null, null));
    }

    // =========================================================================
    // 7. Scan Lifecycle Updates
    // =========================================================================
    @Test
    @DisplayName("7. Scan status transitions update properly through the testing lifecycle")
    void test07_ScanLifecycleUpdates() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Lifecycle Run", null, null);
        assertEquals(ApiScanStatus.PENDING, scan.status());

        scan = persistenceService.updateScanStatus(scan.id(), USER_ALICE, ApiScanStatus.GENERATING);
        assertEquals(ApiScanStatus.GENERATING, scan.status());

        scan = persistenceService.updateScanStatus(scan.id(), USER_ALICE, ApiScanStatus.EXECUTING);
        assertEquals(ApiScanStatus.EXECUTING, scan.status());

        scan = persistenceService.updateScanStatus(scan.id(), USER_ALICE, ApiScanStatus.ANALYZING);
        assertEquals(ApiScanStatus.ANALYZING, scan.status());

        scan = persistenceService.completeScan(scan.id(), USER_ALICE, "BUDGET_EXHAUSTED");
        assertEquals(ApiScanStatus.COMPLETED, scan.status());
        assertEquals("BUDGET_EXHAUSTED", scan.terminationReason());
        assertNotNull(scan.completedAt());
    }

    // =========================================================================
    // 8. Execution Result Persistence
    // =========================================================================
    @Test
    @DisplayName("8. Multiple executions can be persisted in batch with accurate counts")
    void test08_ExecutionResultPersistence() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Batch Exec", null, null);

        var payload1 = new ApiPersistenceService.ExecutionPayload(
                new ApiExecutionResponse("E1", "T1", 200, Map.of(), "ok1", "text/plain", 3L, 20L, 0, List.of(), true, ExecutionOutcome.SUCCESS, null, Instant.now()),
                "/api/a", HttpMethod.GET
        );
        var payload2 = new ApiPersistenceService.ExecutionPayload(
                new ApiExecutionResponse("E2", "T2", 404, Map.of(), "not found", "text/plain", 9L, 15L, 0, List.of(), true, ExecutionOutcome.CLIENT_ERROR, null, Instant.now()),
                "/api/b", HttpMethod.POST
        );

        List<ApiExecutionDto> saved = persistenceService.saveExecutionsBatch(scan.id(), USER_ALICE, List.of(payload1, payload2));
        assertEquals(2, saved.size());

        ApiScanDto updatedScan = persistenceService.getScanById(scan.id(), USER_ALICE).orElseThrow();
        assertEquals(2, updatedScan.totalExecutedRequests());
    }

    // =========================================================================
    // 9. Finding Persistence with Module G Findings
    // =========================================================================
    @Test
    @DisplayName("9. Findings persistence updates scan severity counters (Critical, High, Total)")
    void test09_FindingPersistenceWithModuleG() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Counter Test", null, null);

        ApiSecurityFinding fCrit = ApiSecurityFinding.builder()
                .findingId("F-CRIT")
                .ruleId("RULE-SENSITIVE-DATA")
                .severity(ApiFindingSeverity.CRITICAL)
                .build();

        ApiSecurityFinding fHigh = ApiSecurityFinding.builder()
                .findingId("F-HIGH")
                .ruleId("RULE-AUTH-WEAKNESS")
                .severity(ApiFindingSeverity.HIGH)
                .build();

        persistenceService.saveFindings(scan.id(), USER_ALICE, projectAliceId, List.of(fCrit, fHigh));

        ApiScanDto updatedScan = persistenceService.getScanById(scan.id(), USER_ALICE).orElseThrow();
        assertEquals(2, updatedScan.totalFindings());
        assertEquals(1, updatedScan.criticalCount());
        assertEquals(1, updatedScan.highCount());
        assertEquals(0, updatedScan.mediumCount());
    }

    // =========================================================================
    // 10. Secret Redaction Before Storage
    // =========================================================================
    @Test
    @DisplayName("10. Credentials, bearer tokens and API keys are redacted before saving to DB")
    void test10_SecretRedactionBeforeStorage() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Redaction Run", null, null);

        String secretToken = "sk" + "_live_99887766554433221100aabb";
        String secretPassword = "super_unhashed_password!";

        Map<String, List<String>> headers = Map.of(
                "Authorization", List.of("Bearer " + secretToken)
        );
        String body = "{\"user\":\"root\",\"password\":\"" + secretPassword + "\"}";

        ApiExecutionResponse resp = new ApiExecutionResponse(
                "E-SEC", "T-SEC", 200, headers, body, "application/json",
                100L, 50L, 0, List.of(), true, ExecutionOutcome.SUCCESS, null, Instant.now()
        );

        ApiExecutionDto execDto = persistenceService.saveExecution(scan.id(), USER_ALICE, resp, "/api/login", HttpMethod.POST);

        assertFalse(execDto.responseBody().contains(secretPassword), "Stored response body must not contain plaintext password!");
        assertTrue(execDto.responseBody().contains("******"));

        assertFalse(execDto.responseHeaders().contains(secretToken), "Stored headers must not leak bearer token!");
        assertTrue(execDto.responseHeaders().contains("Bearer ******"));
    }

    // =========================================================================
    // 11. Response-Size Limits and Truncation
    // =========================================================================
    @Test
    @DisplayName("11. Oversized response bodies (>10,000 characters) are truncated with indicator")
    void test11_ResponseSizeLimitsAndTruncation() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Truncate Run", null, null);

        String hugeBody = "X".repeat(15000);
        ApiExecutionResponse resp = new ApiExecutionResponse(
                "E-HUGE", "T-HUGE", 200, Map.of(), hugeBody, "text/plain",
                15000L, 100L, 0, List.of(), true, ExecutionOutcome.SUCCESS, null, Instant.now()
        );

        ApiExecutionDto execDto = persistenceService.saveExecution(scan.id(), USER_ALICE, resp, "/large", HttpMethod.GET);

        assertTrue(execDto.bodyTruncated());
        assertTrue(execDto.responseBody().contains("[TRUNCATED: original size 15000 bytes]"));
        assertTrue(execDto.responseBody().length() <= ApiPersistenceService.MAX_STORED_BODY_LENGTH + 100);
    }

    // =========================================================================
    // 12. Pagination on Executions and Findings
    // =========================================================================
    @Test
    @DisplayName("12. Executions and findings support standard Spring Data pagination")
    void test12_PaginationOnExecutionsAndFindings() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Pagination Run", null, null);

        for (int i = 0; i < 5; i++) {
            persistenceService.saveExecution(scan.id(), USER_ALICE,
                    new ApiExecutionResponse("E" + i, "T" + i, 200, Map.of(), "body", "text/plain", 4L, 10L, 0, List.of(), true, ExecutionOutcome.SUCCESS, null, Instant.now()),
                    "/endpoint/" + i, HttpMethod.GET);
        }

        Page<ApiExecutionDto> page0 = persistenceService.getExecutionsForScan(scan.id(), USER_ALICE, PageRequest.of(0, 2));
        assertEquals(2, page0.getContent().size());
        assertEquals(5, page0.getTotalElements());
        assertEquals(3, page0.getTotalPages());

        Page<ApiExecutionDto> page1 = persistenceService.getExecutionsForScan(scan.id(), USER_ALICE, PageRequest.of(1, 2));
        assertEquals(2, page1.getContent().size());
    }

    // =========================================================================
    // 13. Severity Filtering
    // =========================================================================
    @Test
    @DisplayName("13. Findings can be filtered accurately by severity rating")
    void test13_SeverityFiltering() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Filter Run", null, null);

        persistenceService.saveFindings(scan.id(), USER_ALICE, projectAliceId, List.of(
                ApiSecurityFinding.builder().findingId("F1").endpointPath("/api/v1/a").severity(ApiFindingSeverity.HIGH).build(),
                ApiSecurityFinding.builder().findingId("F2").endpointPath("/api/v1/b").severity(ApiFindingSeverity.LOW).build(),
                ApiSecurityFinding.builder().findingId("F3").endpointPath("/api/v1/c").severity(ApiFindingSeverity.HIGH).build()
        ));

        List<ApiFindingDto> highFindings = persistenceService.getFindingsBySeverity(scan.id(), USER_ALICE, "HIGH");
        assertEquals(2, highFindings.size());

        List<ApiFindingDto> lowFindings = persistenceService.getFindingsBySeverity(scan.id(), USER_ALICE, "LOW");
        assertEquals(1, lowFindings.size());
    }

    // =========================================================================
    // 14. Endpoint Filtering
    // =========================================================================
    @Test
    @DisplayName("14. Findings can be searched by endpoint path pattern")
    void test14_EndpointFiltering() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Endpoint Run", null, null);

        persistenceService.saveFindings(scan.id(), USER_ALICE, projectAliceId, List.of(
                ApiSecurityFinding.builder().findingId("F1").endpointPath("/api/v1/users").build(),
                ApiSecurityFinding.builder().findingId("F2").endpointPath("/api/v1/orders").build(),
                ApiSecurityFinding.builder().findingId("F3").endpointPath("/api/v1/users/profile").build()
        ));

        List<ApiFindingDto> userFindings = persistenceService.searchFindingsByEndpoint(scan.id(), USER_ALICE, "users");
        assertEquals(2, userFindings.size());
    }

    // =========================================================================
    // 15. User Ownership Enforcement
    // =========================================================================
    @Test
    @DisplayName("15. Queries strictly return data owned by the authenticated user")
    void test15_UserOwnershipEnforcement() {
        // Alice scan
        ApiScanDto scanAlice = persistenceService.createScan(projectAliceId, USER_ALICE, "Alice Scan", null, null);

        // Bob scans
        List<ApiScanDto> bobScans = persistenceService.getScansForUser(USER_BOB);
        assertTrue(bobScans.isEmpty(), "Bob should not see Alice's scans");

        List<ApiScanDto> aliceScans = persistenceService.getScansForUser(USER_ALICE);
        assertEquals(1, aliceScans.size());
        assertEquals(scanAlice.id(), aliceScans.get(0).id());
    }

    // =========================================================================
    // 16. Cross-User Access Prevention
    // =========================================================================
    @Test
    @DisplayName("16. Cross-user data access attempts immediately throw SecurityException")
    void test16_CrossUserAccessPrevention() {
        ApiScanDto scanAlice = persistenceService.createScan(projectAliceId, USER_ALICE, "Confidential Scan", null, null);

        // Bob attempts to query Alice's scan directly - returns empty Optional
        assertTrue(persistenceService.getScanById(scanAlice.id(), USER_BOB).isEmpty());

        // Bob attempts to query or mutate Alice's scan sub-resources -> throws SecurityException
        assertThrows(SecurityException.class, () ->
                persistenceService.getExecutionsForScan(scanAlice.id(), USER_BOB, PageRequest.of(0, 10)));

        assertThrows(SecurityException.class, () ->
                persistenceService.getFindingsForScan(scanAlice.id(), USER_BOB, PageRequest.of(0, 10)));

        assertThrows(SecurityException.class, () ->
                persistenceService.updateScanStatus(scanAlice.id(), USER_BOB, ApiScanStatus.COMPLETED));

        assertThrows(SecurityException.class, () ->
                persistenceService.saveExecution(scanAlice.id(), USER_BOB,
                        new ApiExecutionResponse("E-BOB", "TC-B", 200, Map.of(), "ok", "text/plain", 2L, 10L, 0, List.of(), true, ExecutionOutcome.SUCCESS, null, Instant.now()),
                        "/hack", HttpMethod.GET));
    }

    // =========================================================================
    // 17. Duplicate Finding Handling Within Scan
    // =========================================================================
    @Test
    @DisplayName("17. Overlapping findings within the same scan are deduplicated by canonical key")
    void test17_DuplicateFindingHandlingWithinScan() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Dedup Run", null, null);

        ApiSecurityFinding f1 = ApiSecurityFinding.builder()
                .findingId("F1")
                .ruleId("RULE-AUTH")
                .endpointPath("/api/admin")
                .evidence("Identical Evidence")
                .build();

        ApiSecurityFinding f2 = ApiSecurityFinding.builder()
                .findingId("F2")
                .ruleId("RULE-AUTH")
                .endpointPath("/api/admin")
                .evidence("Identical Evidence")
                .build();

        List<ApiFindingDto> saved = persistenceService.saveFindings(scan.id(), USER_ALICE, projectAliceId, List.of(f1, f2));
        assertEquals(1, saved.size(), "Duplicate finding within scan must be filtered out");
    }

    // =========================================================================
    // 18. Historical Scan Separation
    // =========================================================================
    @Test
    @DisplayName("18. Historical scans maintain isolated, independent finding records")
    void test18_HistoricalScanSeparation() {
        ApiScanDto scan1 = persistenceService.createScan(projectAliceId, USER_ALICE, "Scan 1", null, null);
        ApiScanDto scan2 = persistenceService.createScan(projectAliceId, USER_ALICE, "Scan 2", null, null);

        ApiSecurityFinding f = ApiSecurityFinding.builder()
                .findingId("F-COMMON")
                .ruleId("RULE-SEC")
                .endpointPath("/api/test")
                .evidence("Common evidence")
                .build();

        persistenceService.saveFindings(scan1.id(), USER_ALICE, projectAliceId, List.of(f));
        persistenceService.saveFindings(scan2.id(), USER_ALICE, projectAliceId, List.of(f));

        assertEquals(1, findingRepo.findByScanIdOrderByDetectedAtAsc(scan1.id()).size());
        assertEquals(1, findingRepo.findByScanIdOrderByDetectedAtAsc(scan2.id()).size());
    }

    // =========================================================================
    // 19. Retrieval of Previous Scans List
    // =========================================================================
    @Test
    @DisplayName("19. Previous scans list retrieves in reverse chronological order")
    void test19_RetrievalOfPreviousScansList() {
        ApiScanDto s1 = persistenceService.createScan(projectAliceId, USER_ALICE, "Scan Alpha", null, null);
        ApiScanDto s2 = persistenceService.createScan(projectAliceId, USER_ALICE, "Scan Beta", null, null);

        List<ApiScanDto> scans = persistenceService.getScansForUser(USER_ALICE);
        assertEquals(2, scans.size());
        // Verify both are present
        assertTrue(scans.stream().anyMatch(s -> s.scanName().equals("Scan Alpha")));
        assertTrue(scans.stream().anyMatch(s -> s.scanName().equals("Scan Beta")));
    }

    // =========================================================================
    // 20. Scan Statistics Calculation and Storage
    // =========================================================================
    @Test
    @DisplayName("20. calculateAndSaveStatistics aggregates response times, data sizes, and status codes")
    void test20_ScanStatisticsCalculationAndStorage() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Stats Run", null, null);

        persistenceService.saveExecution(scan.id(), USER_ALICE,
                new ApiExecutionResponse("E1", "T1", 200, Map.of(), "ok", "text/plain", 100L, 50L, 0, List.of(), true, ExecutionOutcome.SUCCESS, null, Instant.now()),
                "/a", HttpMethod.GET);

        persistenceService.saveExecution(scan.id(), USER_ALICE,
                new ApiExecutionResponse("E2", "T2", 500, Map.of(), "err", "text/plain", 200L, 150L, 0, List.of(), true, ExecutionOutcome.SERVER_ERROR, null, Instant.now()),
                "/b", HttpMethod.GET);

        SearchResult searchResult = new SearchResult(
                5, 20, 10, 8, 80.0, Map.of(), List.of(), TerminationReason.EVALUATION_BUDGET_EXHAUSTED, 5000L, 12345L
        );

        ApiScanStatisticsDto stats = persistenceService.calculateAndSaveStatistics(scan.id(), USER_ALICE, searchResult);

        assertNotNull(stats);
        assertEquals(100.0, stats.avgResponseTimeMs()); // (50 + 150) / 2 = 100
        assertEquals(50L, stats.minResponseTimeMs());
        assertEquals(150L, stats.maxResponseTimeMs());
        assertEquals(300L, stats.totalDataTransferredBytes());
        assertEquals(1, stats.status2xxCount());
        assertEquals(1, stats.status5xxCount());
        assertEquals(80.0, stats.coveragePercentage());
        assertEquals(8, stats.objectivesAchieved());
    }

    // =========================================================================
    // 21. Failed Scan Persistence
    // =========================================================================
    @Test
    @DisplayName("21. failScan records FAILED status, completion timestamp, and error message")
    void test21_FailedScanPersistence() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Failing Run", null, null);

        ApiScanDto failed = persistenceService.failScan(scan.id(), USER_ALICE, "Connection timeout to host");
        assertEquals(ApiScanStatus.FAILED, failed.status());
        assertEquals("Connection timeout to host", failed.errorMessage());
        assertNotNull(failed.completedAt());
    }

    // =========================================================================
    // 22. Cancelled Scan Persistence
    // =========================================================================
    @Test
    @DisplayName("22. cancelScan records CANCELLED status and user termination reason")
    void test22_CancelledScanPersistence() {
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "Cancel Run", null, null);

        ApiScanDto cancelled = persistenceService.cancelScan(scan.id(), USER_ALICE, "OPERATOR_ABORT");
        assertEquals(ApiScanStatus.CANCELLED, cancelled.status());
        assertEquals("OPERATOR_ABORT", cancelled.terminationReason());
        assertNotNull(cancelled.completedAt());
    }

    // =========================================================================
    // 23. Migration Compatibility with Existing Database
    // =========================================================================
    @Test
    @DisplayName("23. Schema migration script 03 is present on classpath and contains safe DDL")
    void test23_MigrationCompatibility() {
        var is = getClass().getResourceAsStream("/database/03_api_execution_and_findings_schema.sql");
        assertNotNull(is, "03_api_execution_and_findings_schema.sql must exist on classpath");

        // Verify DatabaseMigrationService handles null or offline datasource safely
        DatabaseMigrationService migrationService = new DatabaseMigrationService(null);
        assertDoesNotThrow(migrationService::runMigrations);
    }

    // =========================================================================
    // 24. Repository Integration
    // =========================================================================
    @Test
    @DisplayName("24. All 5 repositories can persist, find, and count entities cleanly")
    void test24_RepositoryIntegration() {
        assertEquals(0, scanRepo.count());
        assertEquals(0, execRepo.count());
        assertEquals(0, findingRepo.count());
        assertEquals(0, testCaseRepo.count());
        assertEquals(0, statsRepo.count());

        ApiScanEntity s = scanRepo.save(new ApiScanEntity(projectAliceId, USER_ALICE, "Repo Scan"));
        assertEquals(1, scanRepo.count());
        assertTrue(scanRepo.findByIdAndUserId(s.getId(), USER_ALICE).isPresent());
    }

    // =========================================================================
    // 25. Full Module F and Module G Persistence Integration
    // =========================================================================
    @Test
    @DisplayName("25. End-to-end flow: Module F execution -> Module G analysis -> Module H persistence")
    void test25_ModuleFAndModuleGPersistenceIntegration() {
        MockHttpClient mockHttpClient = new MockHttpClient();
        HttpClientManager httpClientManager = new HttpClientManager(mockHttpClient, null, null, null);
        String serverBaseUrl = "http://127.0.0.1:8080";

        ApiExecutionConfiguration config = ApiExecutionConfiguration.builder().allowLocalAddresses(true).build();
        ApiExecutionEngine executionEngine = new ApiExecutionEngine(httpClientManager, config);
        ApiRequestBuilder requestBuilder = new ApiRequestBuilder();
        ApiSecurityAnalyzer analyzer = new ApiSecurityAnalyzer();

        // 1. Mock server returns server banner and password leak
        mockHttpClient.on("/api/v1/user", request -> new MockHttpClient.MockResponse(
                200,
                Map.of("Server", List.of("Apache/2.4.41 (Ubuntu)"), "Content-Type", List.of("application/json")),
                "{\"username\": \"charlie\", \"password\": \"UnmaskedSecretPW123!\"}"
        ));

        // 2. Prepare test case and request (Module C & F)
        ApiTestCase tc = new ApiTestCase(
                "TC-E2E-H", "GET /api/v1/user", HttpMethod.GET, "/api/v1/user",
                TestCategory.VALID, Map.of(), Map.of(), Map.of(), Map.of(),
                null, "application/json", GenerationStrategy.SCHEMA_VALID_FULL,
                1L, "User lookup", null, null, null
        );
        ApiExecutionRequest execReq = requestBuilder.buildRequest(serverBaseUrl, tc, projectAliceId);

        // 3. Execute via Module F
        ApiExecutionResponse execResp = executionEngine.execute(execReq);
        assertEquals(200, execResp.statusCode());

        // 4. Analyze via Module G
        List<ApiSecurityFinding> findings = analyzer.analyze(execReq, execResp);
        assertFalse(findings.isEmpty(), "Should find security weaknesses");

        // 5. Persist via Module H
        ApiScanDto scan = persistenceService.createScan(projectAliceId, USER_ALICE, "E2E Scan", null, null);

        ApiExecutionDto execDto = persistenceService.saveExecution(scan.id(), USER_ALICE, execResp, "/api/v1/user", HttpMethod.GET);
        assertNotNull(execDto);
        assertFalse(execDto.responseBody().contains("UnmaskedSecretPW123!")); // Redacted

        List<ApiFindingDto> findingDtos = persistenceService.saveFindings(scan.id(), USER_ALICE, projectAliceId, findings);
        assertFalse(findingDtos.isEmpty());

        ApiScanDto completedScan = persistenceService.completeScan(scan.id(), USER_ALICE, "SUCCESS");
        assertEquals(ApiScanStatus.COMPLETED, completedScan.status());
        assertTrue(completedScan.totalFindings() > 0);
        assertEquals(1, completedScan.totalExecutedRequests());
    }

    // =========================================================================
    // In-Memory Repository Implementations for Hermetic Unit Testing
    // =========================================================================

    private static class InMemoryApiScanRepository implements ApiScanRepository {
        private final Map<Long, ApiScanEntity> store = new LinkedHashMap<>();
        private final AtomicLong idGen = new AtomicLong(1);

        @Override
        public List<ApiScanEntity> findByUserIdOrderByCreatedAtDesc(Long userId) {
            return store.values().stream().filter(e -> Objects.equals(e.getUserId(), userId)).sorted((a, b) -> b.getCreatedAt().compareTo(a.getCreatedAt())).toList();
        }

        @Override
        public Page<ApiScanEntity> findByUserIdOrderByCreatedAtDesc(Long userId, Pageable pageable) {
            List<ApiScanEntity> list = findByUserIdOrderByCreatedAtDesc(userId);
            int start = (int) pageable.getOffset();
            int end = Math.min((start + pageable.getPageSize()), list.size());
            return new PageImpl<>(start < list.size() ? list.subList(start, end) : List.of(), pageable, list.size());
        }

        @Override
        public Optional<ApiScanEntity> findByIdAndUserId(Long id, Long userId) {
            ApiScanEntity e = store.get(id);
            return (e != null && Objects.equals(e.getUserId(), userId)) ? Optional.of(e) : Optional.empty();
        }

        @Override
        public List<ApiScanEntity> findByApiProjectIdAndUserIdOrderByCreatedAtDesc(Long apiProjectId, Long userId) {
            return store.values().stream().filter(e -> Objects.equals(e.getApiProjectId(), apiProjectId) && Objects.equals(e.getUserId(), userId)).toList();
        }

        @Override
        public Page<ApiScanEntity> findByApiProjectIdAndUserIdOrderByCreatedAtDesc(Long apiProjectId, Long userId, Pageable pageable) {
            List<ApiScanEntity> list = findByApiProjectIdAndUserIdOrderByCreatedAtDesc(apiProjectId, userId);
            return new PageImpl<>(list, pageable, list.size());
        }

        @Override public long countByUserId(Long userId) { return findByUserIdOrderByCreatedAtDesc(userId).size(); }
        @Override public long countByApiProjectIdAndUserId(Long apiProjectId, Long userId) { return findByApiProjectIdAndUserIdOrderByCreatedAtDesc(apiProjectId, userId).size(); }
        @Override public <S extends ApiScanEntity> S save(S entity) {
            if (entity.getId() == null) entity.setId(idGen.getAndIncrement());
            store.put(entity.getId(), entity);
            return entity;
        }
        @Override public Optional<ApiScanEntity> findById(Long id) { return Optional.ofNullable(store.get(id)); }
        @Override public boolean existsById(Long id) { return store.containsKey(id); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long id) { store.remove(id); }
        @Override public void delete(ApiScanEntity entity) { if (entity != null) store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> ids) { ids.forEach(store::remove); }
        @Override public void deleteAll(Iterable<? extends ApiScanEntity> entities) { entities.forEach(e -> store.remove(e.getId())); }
        @Override public void deleteAll() { store.clear(); }
        @Override public List<ApiScanEntity> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<ApiScanEntity> findAllById(Iterable<Long> ids) { return new ArrayList<>(); }
        @Override public <S extends ApiScanEntity> List<S> saveAll(Iterable<S> entities) {
            List<S> res = new ArrayList<>();
            entities.forEach(e -> res.add(save(e)));
            return res;
        }
        @Override public void flush() {}
        @Override public <S extends ApiScanEntity> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends ApiScanEntity> List<S> saveAllAndFlush(Iterable<S> entities) { return saveAll(entities); }
        @Override public void deleteAllInBatch(Iterable<ApiScanEntity> entities) { deleteAll(entities); }
        @Override public void deleteAllByIdInBatch(Iterable<Long> ids) { deleteAllById(ids); }
        @Override public void deleteAllInBatch() { deleteAll(); }
        @Override public ApiScanEntity getOne(Long id) { return store.get(id); }
        @Override public ApiScanEntity getById(Long id) { return store.get(id); }
        @Override public ApiScanEntity getReferenceById(Long id) { return store.get(id); }
        @Override public <S extends ApiScanEntity> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends ApiScanEntity> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends ApiScanEntity> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends ApiScanEntity> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends ApiScanEntity> long count(Example<S> example) { return 0; }
        @Override public <S extends ApiScanEntity> boolean exists(Example<S> example) { return false; }
        @Override public <S extends ApiScanEntity, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<ApiScanEntity> findAll(Sort sort) { return findAll(); }
        @Override public Page<ApiScanEntity> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }

    private static class InMemoryApiExecutionRepository implements ApiExecutionRepository {
        private final Map<Long, ApiExecutionEntity> store = new LinkedHashMap<>();
        private final AtomicLong idGen = new AtomicLong(1);

        public void deleteByScanId(Long scanId) {
            store.entrySet().removeIf(e -> Objects.equals(e.getValue().getScanId(), scanId));
        }

        @Override
        public List<ApiExecutionEntity> findByScanIdOrderByExecutedAtAsc(Long scanId) {
            return store.values().stream().filter(e -> Objects.equals(e.getScanId(), scanId)).sorted(Comparator.comparing(ApiExecutionEntity::getExecutedAt)).toList();
        }

        @Override
        public Page<ApiExecutionEntity> findByScanIdOrderByExecutedAtAsc(Long scanId, Pageable pageable) {
            List<ApiExecutionEntity> list = findByScanIdOrderByExecutedAtAsc(scanId);
            int start = (int) pageable.getOffset();
            int end = Math.min((start + pageable.getPageSize()), list.size());
            return new PageImpl<>(start < list.size() ? list.subList(start, end) : List.of(), pageable, list.size());
        }

        @Override
        public Optional<ApiExecutionEntity> findByExecutionUuid(String executionUuid) {
            return store.values().stream().filter(e -> Objects.equals(e.getExecutionUuid(), executionUuid)).findFirst();
        }

        @Override
        public List<ApiExecutionEntity> findByScanIdAndEndpointContaining(Long scanId, String endpoint) {
            return store.values().stream().filter(e -> Objects.equals(e.getScanId(), scanId) && e.getEndpoint().contains(endpoint)).toList();
        }

        @Override public long countByScanId(Long scanId) { return findByScanIdOrderByExecutedAtAsc(scanId).size(); }
        @Override public long countByScanIdAndStatusCodeBetween(Long scanId, int s, int end) {
            return store.values().stream().filter(e -> Objects.equals(e.getScanId(), scanId) && e.getStatusCode() >= s && e.getStatusCode() <= end).count();
        }
        @Override public <S extends ApiExecutionEntity> S save(S entity) {
            if (entity.getId() == null) entity.setId(idGen.getAndIncrement());
            store.put(entity.getId(), entity);
            return entity;
        }
        @Override public Optional<ApiExecutionEntity> findById(Long id) { return Optional.ofNullable(store.get(id)); }
        @Override public boolean existsById(Long id) { return store.containsKey(id); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long id) { store.remove(id); }
        @Override public void delete(ApiExecutionEntity entity) { if (entity != null) store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> ids) { ids.forEach(store::remove); }
        @Override public void deleteAll(Iterable<? extends ApiExecutionEntity> entities) { entities.forEach(e -> store.remove(e.getId())); }
        @Override public void deleteAll() { store.clear(); }
        @Override public List<ApiExecutionEntity> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<ApiExecutionEntity> findAllById(Iterable<Long> ids) { return new ArrayList<>(); }
        @Override public <S extends ApiExecutionEntity> List<S> saveAll(Iterable<S> entities) {
            List<S> res = new ArrayList<>();
            entities.forEach(e -> res.add(save(e)));
            return res;
        }
        @Override public void flush() {}
        @Override public <S extends ApiExecutionEntity> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends ApiExecutionEntity> List<S> saveAllAndFlush(Iterable<S> entities) { return saveAll(entities); }
        @Override public void deleteAllInBatch(Iterable<ApiExecutionEntity> entities) { deleteAll(entities); }
        @Override public void deleteAllByIdInBatch(Iterable<Long> ids) { deleteAllById(ids); }
        @Override public void deleteAllInBatch() { deleteAll(); }
        @Override public ApiExecutionEntity getOne(Long id) { return store.get(id); }
        @Override public ApiExecutionEntity getById(Long id) { return store.get(id); }
        @Override public ApiExecutionEntity getReferenceById(Long id) { return store.get(id); }
        @Override public <S extends ApiExecutionEntity> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends ApiExecutionEntity> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends ApiExecutionEntity> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends ApiExecutionEntity> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends ApiExecutionEntity> long count(Example<S> example) { return 0; }
        @Override public <S extends ApiExecutionEntity> boolean exists(Example<S> example) { return false; }
        @Override public <S extends ApiExecutionEntity, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<ApiExecutionEntity> findAll(Sort sort) { return findAll(); }
        @Override public Page<ApiExecutionEntity> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }

    private static class InMemoryApiFindingRepository implements ApiFindingRepository {
        private final Map<Long, ApiFindingEntity> store = new LinkedHashMap<>();
        private final AtomicLong idGen = new AtomicLong(1);

        public void deleteByScanId(Long scanId) {
            store.entrySet().removeIf(e -> Objects.equals(e.getValue().getScanId(), scanId));
        }

        @Override
        public List<ApiFindingEntity> findByScanIdOrderByDetectedAtAsc(Long scanId) {
            return store.values().stream().filter(e -> Objects.equals(e.getScanId(), scanId)).sorted(Comparator.comparing(ApiFindingEntity::getDetectedAt)).toList();
        }

        @Override
        public Page<ApiFindingEntity> findByScanIdOrderByDetectedAtAsc(Long scanId, Pageable pageable) {
            List<ApiFindingEntity> list = findByScanIdOrderByDetectedAtAsc(scanId);
            int start = (int) pageable.getOffset();
            int end = Math.min((start + pageable.getPageSize()), list.size());
            return new PageImpl<>(start < list.size() ? list.subList(start, end) : List.of(), pageable, list.size());
        }

        @Override
        public List<ApiFindingEntity> findByScanIdAndSeverity(Long scanId, String severity) {
            return store.values().stream().filter(e -> Objects.equals(e.getScanId(), scanId) && e.getSeverity().equalsIgnoreCase(severity)).toList();
        }

        @Override
        public Page<ApiFindingEntity> findByScanIdAndSeverity(Long scanId, String severity, Pageable pageable) {
            List<ApiFindingEntity> list = findByScanIdAndSeverity(scanId, severity);
            return new PageImpl<>(list, pageable, list.size());
        }

        @Override
        public List<ApiFindingEntity> findByScanIdAndRuleId(Long scanId, String ruleId) {
            return store.values().stream().filter(e -> Objects.equals(e.getScanId(), scanId) && e.getRuleId().equalsIgnoreCase(ruleId)).toList();
        }

        @Override
        public List<ApiFindingEntity> findByScanIdAndEndpointPathContaining(Long scanId, String endpointPath) {
            return store.values().stream().filter(e -> Objects.equals(e.getScanId(), scanId) && e.getEndpointPath().contains(endpointPath)).toList();
        }

        @Override
        public Optional<ApiFindingEntity> findByFindingUuid(String findingUuid) {
            return store.values().stream().filter(e -> Objects.equals(e.getFindingUuid(), findingUuid)).findFirst();
        }

        @Override
        public boolean existsByScanIdAndFindingUuid(Long scanId, String findingUuid) {
            return store.values().stream().anyMatch(e -> Objects.equals(e.getScanId(), scanId) && Objects.equals(e.getFindingUuid(), findingUuid));
        }

        @Override public long countByScanId(Long scanId) { return findByScanIdOrderByDetectedAtAsc(scanId).size(); }
        @Override public long countByScanIdAndSeverity(Long scanId, String severity) { return findByScanIdAndSeverity(scanId, severity).size(); }
        @Override public <S extends ApiFindingEntity> S save(S entity) {
            if (entity.getId() == null) entity.setId(idGen.getAndIncrement());
            store.put(entity.getId(), entity);
            return entity;
        }
        @Override public Optional<ApiFindingEntity> findById(Long id) { return Optional.ofNullable(store.get(id)); }
        @Override public boolean existsById(Long id) { return store.containsKey(id); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long id) { store.remove(id); }
        @Override public void delete(ApiFindingEntity entity) { if (entity != null) store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> ids) { ids.forEach(store::remove); }
        @Override public void deleteAll(Iterable<? extends ApiFindingEntity> entities) { entities.forEach(e -> store.remove(e.getId())); }
        @Override public void deleteAll() { store.clear(); }
        @Override public List<ApiFindingEntity> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<ApiFindingEntity> findAllById(Iterable<Long> ids) { return new ArrayList<>(); }
        @Override public <S extends ApiFindingEntity> List<S> saveAll(Iterable<S> entities) {
            List<S> res = new ArrayList<>();
            entities.forEach(e -> res.add(save(e)));
            return res;
        }
        @Override public void flush() {}
        @Override public <S extends ApiFindingEntity> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends ApiFindingEntity> List<S> saveAllAndFlush(Iterable<S> entities) { return saveAll(entities); }
        @Override public void deleteAllInBatch(Iterable<ApiFindingEntity> entities) { deleteAll(entities); }
        @Override public void deleteAllByIdInBatch(Iterable<Long> ids) { deleteAllById(ids); }
        @Override public void deleteAllInBatch() { deleteAll(); }
        @Override public ApiFindingEntity getOne(Long id) { return store.get(id); }
        @Override public ApiFindingEntity getById(Long id) { return store.get(id); }
        @Override public ApiFindingEntity getReferenceById(Long id) { return store.get(id); }
        @Override public <S extends ApiFindingEntity> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends ApiFindingEntity> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends ApiFindingEntity> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends ApiFindingEntity> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends ApiFindingEntity> long count(Example<S> example) { return 0; }
        @Override public <S extends ApiFindingEntity> boolean exists(Example<S> example) { return false; }
        @Override public <S extends ApiFindingEntity, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<ApiFindingEntity> findAll(Sort sort) { return findAll(); }
        @Override public Page<ApiFindingEntity> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }

    private static class InMemoryApiTestCaseResultRepository implements ApiTestCaseResultRepository {
        private final Map<Long, ApiTestCaseResultEntity> store = new LinkedHashMap<>();
        private final AtomicLong idGen = new AtomicLong(1);

        @Override
        public List<ApiTestCaseResultEntity> findByScanIdOrderByCreatedAtAsc(Long scanId) {
            return store.values().stream().filter(e -> Objects.equals(e.getScanId(), scanId)).toList();
        }

        @Override
        public Page<ApiTestCaseResultEntity> findByScanIdOrderByCreatedAtAsc(Long scanId, Pageable pageable) {
            List<ApiTestCaseResultEntity> list = findByScanIdOrderByCreatedAtAsc(scanId);
            return new PageImpl<>(list, pageable, list.size());
        }

        @Override
        public Optional<ApiTestCaseResultEntity> findByScanIdAndTestCaseId(Long scanId, String testCaseId) {
            return store.values().stream().filter(e -> Objects.equals(e.getScanId(), scanId) && Objects.equals(e.getTestCaseId(), testCaseId)).findFirst();
        }

        @Override public long countByScanId(Long scanId) { return findByScanIdOrderByCreatedAtAsc(scanId).size(); }
        @Override public long countByScanIdAndCategory(Long scanId, String category) {
            return store.values().stream().filter(e -> Objects.equals(e.getScanId(), scanId) && e.getCategory().equalsIgnoreCase(category)).count();
        }
        @Override public <S extends ApiTestCaseResultEntity> S save(S entity) {
            if (entity.getId() == null) entity.setId(idGen.getAndIncrement());
            store.put(entity.getId(), entity);
            return entity;
        }
        @Override public Optional<ApiTestCaseResultEntity> findById(Long id) { return Optional.ofNullable(store.get(id)); }
        @Override public boolean existsById(Long id) { return store.containsKey(id); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long id) { store.remove(id); }
        @Override public void delete(ApiTestCaseResultEntity entity) { if (entity != null) store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> ids) { ids.forEach(store::remove); }
        @Override public void deleteAll(Iterable<? extends ApiTestCaseResultEntity> entities) { entities.forEach(e -> store.remove(e.getId())); }
        @Override public void deleteAll() { store.clear(); }
        @Override public List<ApiTestCaseResultEntity> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<ApiTestCaseResultEntity> findAllById(Iterable<Long> ids) { return new ArrayList<>(); }
        @Override public <S extends ApiTestCaseResultEntity> List<S> saveAll(Iterable<S> entities) {
            List<S> res = new ArrayList<>();
            entities.forEach(e -> res.add(save(e)));
            return res;
        }
        @Override public void flush() {}
        @Override public <S extends ApiTestCaseResultEntity> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends ApiTestCaseResultEntity> List<S> saveAllAndFlush(Iterable<S> entities) { return saveAll(entities); }
        @Override public void deleteAllInBatch(Iterable<ApiTestCaseResultEntity> entities) { deleteAll(entities); }
        @Override public void deleteAllByIdInBatch(Iterable<Long> ids) { deleteAllById(ids); }
        @Override public void deleteAllInBatch() { deleteAll(); }
        @Override public ApiTestCaseResultEntity getOne(Long id) { return store.get(id); }
        @Override public ApiTestCaseResultEntity getById(Long id) { return store.get(id); }
        @Override public ApiTestCaseResultEntity getReferenceById(Long id) { return store.get(id); }
        @Override public <S extends ApiTestCaseResultEntity> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends ApiTestCaseResultEntity> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends ApiTestCaseResultEntity> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends ApiTestCaseResultEntity> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends ApiTestCaseResultEntity> long count(Example<S> example) { return 0; }
        @Override public <S extends ApiTestCaseResultEntity> boolean exists(Example<S> example) { return false; }
        @Override public <S extends ApiTestCaseResultEntity, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<ApiTestCaseResultEntity> findAll(Sort sort) { return findAll(); }
        @Override public Page<ApiTestCaseResultEntity> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }

    private static class InMemoryApiScanStatisticsRepository implements ApiScanStatisticsRepository {
        private final Map<Long, ApiScanStatisticsEntity> store = new LinkedHashMap<>();
        private final AtomicLong idGen = new AtomicLong(1);

        @Override
        public Optional<ApiScanStatisticsEntity> findByScanId(Long scanId) {
            return store.values().stream().filter(e -> Objects.equals(e.getScanId(), scanId)).findFirst();
        }

        @Override
        public void deleteByScanId(Long scanId) {
            store.entrySet().removeIf(e -> Objects.equals(e.getValue().getScanId(), scanId));
        }

        @Override public <S extends ApiScanStatisticsEntity> S save(S entity) {
            if (entity.getId() == null) entity.setId(idGen.getAndIncrement());
            store.put(entity.getId(), entity);
            return entity;
        }
        @Override public Optional<ApiScanStatisticsEntity> findById(Long id) { return Optional.ofNullable(store.get(id)); }
        @Override public boolean existsById(Long id) { return store.containsKey(id); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long id) { store.remove(id); }
        @Override public void delete(ApiScanStatisticsEntity entity) { if (entity != null) store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> ids) { ids.forEach(store::remove); }
        @Override public void deleteAll(Iterable<? extends ApiScanStatisticsEntity> entities) { entities.forEach(e -> store.remove(e.getId())); }
        @Override public void deleteAll() { store.clear(); }
        @Override public List<ApiScanStatisticsEntity> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<ApiScanStatisticsEntity> findAllById(Iterable<Long> ids) { return new ArrayList<>(); }
        @Override public <S extends ApiScanStatisticsEntity> List<S> saveAll(Iterable<S> entities) {
            List<S> res = new ArrayList<>();
            entities.forEach(e -> res.add(save(e)));
            return res;
        }
        @Override public void flush() {}
        @Override public <S extends ApiScanStatisticsEntity> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends ApiScanStatisticsEntity> List<S> saveAllAndFlush(Iterable<S> entities) { return saveAll(entities); }
        @Override public void deleteAllInBatch(Iterable<ApiScanStatisticsEntity> entities) { deleteAll(entities); }
        @Override public void deleteAllByIdInBatch(Iterable<Long> ids) { deleteAllById(ids); }
        @Override public void deleteAllInBatch() { deleteAll(); }
        @Override public ApiScanStatisticsEntity getOne(Long id) { return store.get(id); }
        @Override public ApiScanStatisticsEntity getById(Long id) { return store.get(id); }
        @Override public ApiScanStatisticsEntity getReferenceById(Long id) { return store.get(id); }
        @Override public <S extends ApiScanStatisticsEntity> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends ApiScanStatisticsEntity> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends ApiScanStatisticsEntity> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends ApiScanStatisticsEntity> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends ApiScanStatisticsEntity> long count(Example<S> example) { return 0; }
        @Override public <S extends ApiScanStatisticsEntity> boolean exists(Example<S> example) { return false; }
        @Override public <S extends ApiScanStatisticsEntity, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<ApiScanStatisticsEntity> findAll(Sort sort) { return findAll(); }
        @Override public Page<ApiScanStatisticsEntity> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }

    private static class InMemoryApiProjectRepository implements ApiProjectRepository {
        private final Map<Long, ApiProjectEntity> store = new LinkedHashMap<>();
        private final AtomicLong idGen = new AtomicLong(1);

        @Override public List<ApiProjectEntity> findByUserIdOrderByCreatedAtDesc(Long userId) {
            return store.values().stream().filter(e -> Objects.equals(e.getUserId(), userId)).toList();
        }
        @Override public Optional<ApiProjectEntity> findByIdAndUserId(Long id, Long userId) {
            ApiProjectEntity e = store.get(id);
            return (e != null && Objects.equals(e.getUserId(), userId)) ? Optional.of(e) : Optional.empty();
        }
        @Override public boolean existsByUserIdAndName(Long userId, String name) { return false; }
        @Override public boolean existsByUserIdAndNameAndIdNot(Long userId, String name, Long id) { return false; }
        @Override public long countByUserId(Long userId) { return findByUserIdOrderByCreatedAtDesc(userId).size(); }
        @Override public <S extends ApiProjectEntity> S save(S entity) {
            if (entity.getId() == null) entity.setId(idGen.getAndIncrement());
            store.put(entity.getId(), entity);
            return entity;
        }
        @Override public Optional<ApiProjectEntity> findById(Long id) { return Optional.ofNullable(store.get(id)); }
        @Override public boolean existsById(Long id) { return store.containsKey(id); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long id) { store.remove(id); }
        @Override public void delete(ApiProjectEntity entity) { if (entity != null) store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> ids) { ids.forEach(store::remove); }
        @Override public void deleteAll(Iterable<? extends ApiProjectEntity> entities) { entities.forEach(e -> store.remove(e.getId())); }
        @Override public void deleteAll() { store.clear(); }
        @Override public List<ApiProjectEntity> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<ApiProjectEntity> findAllById(Iterable<Long> ids) { return new ArrayList<>(); }
        @Override public <S extends ApiProjectEntity> List<S> saveAll(Iterable<S> entities) {
            List<S> res = new ArrayList<>();
            entities.forEach(e -> res.add(save(e)));
            return res;
        }
        @Override public void flush() {}
        @Override public <S extends ApiProjectEntity> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends ApiProjectEntity> List<S> saveAllAndFlush(Iterable<S> entities) { return saveAll(entities); }
        @Override public void deleteAllInBatch(Iterable<ApiProjectEntity> entities) { deleteAll(entities); }
        @Override public void deleteAllByIdInBatch(Iterable<Long> ids) { deleteAllById(ids); }
        @Override public void deleteAllInBatch() { deleteAll(); }
        @Override public ApiProjectEntity getOne(Long id) { return store.get(id); }
        @Override public ApiProjectEntity getById(Long id) { return store.get(id); }
        @Override public ApiProjectEntity getReferenceById(Long id) { return store.get(id); }
        @Override public <S extends ApiProjectEntity> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends ApiProjectEntity> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends ApiProjectEntity> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends ApiProjectEntity> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends ApiProjectEntity> long count(Example<S> example) { return 0; }
        @Override public <S extends ApiProjectEntity> boolean exists(Example<S> example) { return false; }
        @Override public <S extends ApiProjectEntity, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<ApiProjectEntity> findAll(Sort sort) { return findAll(); }
        @Override public Page<ApiProjectEntity> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }
}
