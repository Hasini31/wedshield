package com.webshield.api.reporting;

import com.webshield.api.dto.ApiExecutionDto;
import com.webshield.api.dto.ApiFindingDto;
import com.webshield.api.dto.ApiScanDto;
import com.webshield.api.models.*;
import com.webshield.api.repository.ApiReportRepository;
import com.webshield.api.service.ApiPersistenceService;
import com.webshield.api.service.ApiProjectService;
import com.webshield.database.entities.ApiReportEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class ApiReportServiceTest {

    @TempDir
    Path tempDir;

    private TestApiPersistenceService persistenceService;
    private TestApiProjectService projectService;
    private TestApiReportRepository reportRepository;
    private ApiReportService reportService;

    @BeforeEach
    void setUp() {
        persistenceService = new TestApiPersistenceService();
        projectService = new TestApiProjectService();
        reportRepository = new TestApiReportRepository();
        reportService = new ApiReportService(persistenceService, projectService, reportRepository, null);
    }

    private ApiScanDto createTestScan(Long id, Long projectId, Long userId, String name, int findingsCount, int crit, int high) {
        return new ApiScanDto(
                id, projectId, userId, name, ApiScanStatus.COMPLETED,
                LocalDateTime.now().minusMinutes(5), LocalDateTime.now(),
                4500L, 5, 20, 20, findingsCount, crit, high, 1, 0, 0,
                "{}", "{}", "COMPLETED", null,
                LocalDateTime.now().minusMinutes(5), LocalDateTime.now()
        );
    }

    private ApiFindingDto createTestFinding(Long id, Long scanId, String title, String severity, String cwe, String owasp) {
        return new ApiFindingDto(
                id, "uuid-" + id, scanId, 1L, "exec-" + id, "RULE-1",
                title, "Test finding description", severity, "HIGH",
                "GET", "/api/v1/resource", "id", "Sample evidence param=secretToken123",
                cwe, owasp, "Validate input strictly.", false, "NEW", LocalDateTime.now()
        );
    }

    @Test
    @DisplayName("01: HTML Report Generation with findings and OWASP/CWE mappings")
    void testHtmlReportGenerationSuccess() throws IOException {
        Long scanId = 101L;
        Long userId = 1L;
        ApiScanDto scan = createTestScan(scanId, 1L, userId, "Scan-Alpha", 2, 1, 1);
        persistenceService.scans.add(scan);

        ApiFindingDto f1 = createTestFinding(1L, scanId, "SQL Injection in User Profile", "CRITICAL", "CWE-89", "API1:2023");
        ApiFindingDto f2 = createTestFinding(2L, scanId, "Sensitive Data in Response", "HIGH", "CWE-200", "API3:2023");
        persistenceService.findings.addAll(List.of(f1, f2));

        ApiReportConfiguration config = new ApiReportConfiguration(
                "Custom API Security Report",
                ApiReportConfiguration.FORMAT_HTML,
                true, true, true, true, true, true, true, true, false, false,
                tempDir.toString()
        );

        ApiReportExportResult result = reportService.generateReport(scanId, userId, config);

        assertNotNull(result);
        assertTrue(result.success());
        assertEquals(ApiReportConfiguration.FORMAT_HTML, result.reportFormat());
        assertNotNull(result.filePath());
        assertTrue(Files.exists(result.filePath()));
        assertTrue(result.fileSizeBytes() > 0);

        String html = Files.readString(result.filePath());
        assertTrue(html.contains("Custom API Security Report"));
        assertTrue(html.contains("SQL Injection in User Profile"));
        assertTrue(html.contains("CWE-89"));
        assertTrue(html.contains("API1:2023"));
        assertTrue(html.contains("Executive Summary"));
        assertTrue(html.contains("Prioritized Remediation Roadmap"));
    }

    @Test
    @DisplayName("02: PDF Report Generation creates valid PDF structure")
    void testPdfReportGenerationSuccess() throws IOException {
        Long scanId = 102L;
        Long userId = 1L;
        ApiScanDto scan = createTestScan(scanId, 1L, userId, "Scan-Beta", 1, 1, 0);
        persistenceService.scans.add(scan);

        ApiFindingDto f = createTestFinding(10L, scanId, "Broken Object Level Authorization", "CRITICAL", "CWE-284", "API1:2023");
        persistenceService.findings.add(f);

        ApiReportConfiguration config = new ApiReportConfiguration(
                "Executive Security Report",
                ApiReportConfiguration.FORMAT_PDF,
                true, true, true, true, true, true, true, true, false, false,
                tempDir.toString()
        );

        ApiReportExportResult result = reportService.generateReport(scanId, userId, config);

        assertNotNull(result);
        assertTrue(result.success());
        assertEquals(ApiReportConfiguration.FORMAT_PDF, result.reportFormat());
        assertTrue(Files.exists(result.filePath()));

        byte[] pdfBytes = Files.readAllBytes(result.filePath());
        assertTrue(pdfBytes.length > 200);
        String header = new String(pdfBytes, 0, Math.min(pdfBytes.length, 10));
        assertTrue(header.startsWith("%PDF-1.4"), "Must start with valid PDF 1.4 header");

        String tail = new String(pdfBytes, Math.max(0, pdfBytes.length - 100), Math.min(pdfBytes.length, 100));
        assertTrue(tail.contains("%%EOF"), "Must end with standard PDF EOF marker");
    }

    @Test
    @DisplayName("03: Empty scan handling generates clean reports without errors")
    void testEmptyScanReportGeneration() throws IOException {
        Long scanId = 103L;
        Long userId = 1L;
        ApiScanDto scan = createTestScan(scanId, 1L, userId, "Clean-Scan", 0, 0, 0);
        persistenceService.scans.add(scan);

        ApiReportConfiguration config = new ApiReportConfiguration(
                "Clean Report",
                ApiReportConfiguration.FORMAT_HTML,
                true, true, true, true, true, true, true, true, false, false,
                tempDir.toString()
        );

        ApiReportExportResult result = reportService.generateReport(scanId, userId, config);

        assertTrue(result.success());
        String html = Files.readString(result.filePath());
        assertTrue(html.contains("No security findings were identified"));
    }

    @Test
    @DisplayName("04: Path traversal prevention detects directory escapes")
    void testPathTraversalPrevention() {
        HtmlReportGenerator htmlGen = new HtmlReportGenerator();
        ApiReportData data = new ApiReportData(
                "../../../etc/passwd",
                "Target",
                "../../malicious",
                LocalDateTime.now(),
                createTestScan(1L, 1L, 1L, "scan", 0, 0, 0),
                null, List.of(), Optional.empty(), List.of(), Map.of()
        );

        ApiReportConfiguration config = ApiReportConfiguration.defaultHtml();
        ApiReportExportResult res = htmlGen.generate(data, config, tempDir);

        assertTrue(res.success());
        // Verify output file remained firmly confined within tempDir
        assertTrue(res.filePath().startsWith(tempDir.toAbsolutePath()));
        assertFalse(res.filePath().toString().contains(".."));
    }

    @Test
    @DisplayName("05: User ownership validation throws SecurityException on cross-user scan access")
    void testUserOwnershipEnforcement() {
        Long scanId = 200L;
        Long ownerId = 1L;
        Long attackerId = 99L;

        persistenceService.scans.add(createTestScan(scanId, 1L, ownerId, "Private-Scan", 0, 0, 0));

        assertThrows(SecurityException.class, () ->
                reportService.generateReport(scanId, attackerId, ApiReportConfiguration.defaultPdf())
        );
    }

    @Test
    @DisplayName("06: Report metadata persistence and deletion cascading")
    void testReportPersistenceAndDeletion() {
        Long scanId = 105L;
        Long userId = 1L;
        persistenceService.scans.add(createTestScan(scanId, 1L, userId, "Persisted-Scan", 0, 0, 0));

        ApiReportExportResult result = reportService.generateReport(scanId, userId, ApiReportConfiguration.defaultPdf());
        assertTrue(result.success());
        assertEquals(1, reportRepository.entities.size());

        List<ApiReportMetadata> reports = reportService.getReportsForUser(userId);
        assertEquals(1, reports.size());
        assertEquals(scanId, reports.get(0).apiScanId());

        Long reportId = reports.get(0).id();
        reportService.deleteReport(reportId, userId);
        assertEquals(0, reportRepository.entities.size());
        assertFalse(Files.exists(result.filePath()), "Physical file should be deleted on deletion");
    }

    @Test
    @DisplayName("07: Sensitive credentials redaction in report findings")
    void testSensitiveCredentialsRedaction() throws IOException {
        Long scanId = 106L;
        Long userId = 1L;
        persistenceService.scans.add(createTestScan(scanId, 1L, userId, "Redact-Scan", 1, 0, 1));

        String rawEvidence = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretToken\napi_key=AIzaSyD-1234567890\npassword=SuperSecret123!";
        ApiFindingDto f = new ApiFindingDto(
                99L, "uuid-99", scanId, 1L, "exec-99", "RULE-LEAK",
                "Leaked Credentials", "Found secrets in headers", "HIGH", "HIGH",
                "POST", "/api/v1/auth", "password", rawEvidence,
                "CWE-522", "API2:2023", "Rotate credentials immediately.", false, "NEW", LocalDateTime.now()
        );
        persistenceService.findings.add(f);

        ApiReportExportResult result = reportService.generateReport(scanId, userId, ApiReportConfiguration.defaultHtml());
        assertTrue(result.success());

        String html = Files.readString(result.filePath());
        assertFalse(html.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretToken"), "JWT token must be redacted");
        assertFalse(html.contains("SuperSecret123!"), "Plaintext password must be redacted");
        assertTrue(html.contains("******"), "Redaction marker must be present");
    }

    // In-memory stubs
    static class TestApiPersistenceService extends ApiPersistenceService {
        final List<ApiScanDto> scans = new ArrayList<>();
        final List<ApiFindingDto> findings = new ArrayList<>();
        final List<ApiExecutionDto> executions = new ArrayList<>();

        public TestApiPersistenceService() {
            super(null, null, null, null, null, null);
        }

        @Override
        public List<ApiScanDto> getScansForUser(Long userId) {
            return scans.stream().filter(s -> s.userId().equals(userId)).toList();
        }

        @Override
        public List<ApiFindingDto> getFindingsForScan(Long scanId, Long userId) {
            return findings.stream().filter(f -> f.scanId().equals(scanId)).toList();
        }

        @Override
        public List<ApiExecutionDto> getExecutionsForScan(Long scanId, Long userId) {
            return executions.stream().filter(e -> e.scanId().equals(scanId)).toList();
        }
    }

    static class TestApiProjectService extends ApiProjectService {
        public TestApiProjectService() {
            super(null, null);
        }

        @Override
        public Optional<ApiProject> getProject(Long id) {
            ApiProject p = new ApiProject();
            p.setId(id);
            p.setName("Sample PetStore API");
            p.setSourceUrl("https://petstore.example.com/v1");
            p.setSpecType(SpecType.OPENAPI_3);
            p.setSpecFormat(SpecFormat.YAML);
            return Optional.of(p);
        }
    }

    static class TestApiReportRepository implements ApiReportRepository {
        final List<ApiReportEntity> entities = new ArrayList<>();
        long idSeq = 1L;

        @Override
        public <S extends ApiReportEntity> S save(S entity) {
            if (entity.getId() == null) {
                entity.setId(idSeq++);
            }
            entities.removeIf(e -> e.getId().equals(entity.getId()));
            entities.add(entity);
            return entity;
        }

        @Override
        public List<ApiReportEntity> findByUserIdOrderByCreatedAtDesc(Long userId) {
            return entities.stream().filter(e -> e.getUserId().equals(userId)).toList();
        }

        @Override
        public List<ApiReportEntity> findByApiScanIdAndUserIdOrderByCreatedAtDesc(Long apiScanId, Long userId) {
            return entities.stream().filter(e -> e.getApiScanId().equals(apiScanId) && e.getUserId().equals(userId)).toList();
        }

        @Override
        public Optional<ApiReportEntity> findByIdAndUserId(Long id, Long userId) {
            return entities.stream().filter(e -> e.getId().equals(id) && e.getUserId().equals(userId)).findFirst();
        }

        @Override
        public void deleteByIdAndUserId(Long id, Long userId) {
            entities.removeIf(e -> e.getId().equals(id) && e.getUserId().equals(userId));
        }

        @Override
        public void delete(ApiReportEntity entity) {
            entities.removeIf(e -> e.getId().equals(entity.getId()));
        }

        // Minimal unused boilerplate
        @Override public void flush() {}
        @Override public <S extends ApiReportEntity> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends ApiReportEntity> List<S> saveAllAndFlush(Iterable<S> entities) { return List.of(); }
        @Override public void deleteAllInBatch(Iterable<ApiReportEntity> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
        @Override public void deleteAllInBatch() {}
        @Override public ApiReportEntity getOne(Long aLong) { return null; }
        @Override public ApiReportEntity getById(Long aLong) { return null; }
        @Override public ApiReportEntity getReferenceById(Long aLong) { return null; }
        @Override public <S extends ApiReportEntity> Optional<S> findOne(org.springframework.data.domain.Example<S> example) { return Optional.empty(); }
        @Override public <S extends ApiReportEntity> List<S> findAll(org.springframework.data.domain.Example<S> example) { return List.of(); }
        @Override public <S extends ApiReportEntity> List<S> findAll(org.springframework.data.domain.Example<S> example, org.springframework.data.domain.Sort sort) { return List.of(); }
        @Override public <S extends ApiReportEntity> org.springframework.data.domain.Page<S> findAll(org.springframework.data.domain.Example<S> example, org.springframework.data.domain.Pageable pageable) { return null; }
        @Override public <S extends ApiReportEntity> long count(org.springframework.data.domain.Example<S> example) { return 0; }
        @Override public <S extends ApiReportEntity> boolean exists(org.springframework.data.domain.Example<S> example) { return false; }
        @Override public <S extends ApiReportEntity, R> R findBy(org.springframework.data.domain.Example<S> example, java.util.function.Function<org.springframework.data.repository.query.FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public <S extends ApiReportEntity> List<S> saveAll(Iterable<S> entities) { return List.of(); }
        @Override public Optional<ApiReportEntity> findById(Long aLong) { return entities.stream().filter(e -> e.getId().equals(aLong)).findFirst(); }
        @Override public boolean existsById(Long aLong) { return false; }
        @Override public List<ApiReportEntity> findAll() { return entities; }
        @Override public List<ApiReportEntity> findAllById(Iterable<Long> longs) { return List.of(); }
        @Override public long count() { return entities.size(); }
        @Override public void deleteById(Long aLong) { entities.removeIf(e -> e.getId().equals(aLong)); }
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends ApiReportEntity> entities) {}
        @Override public void deleteAll() { entities.clear(); }
        @Override public List<ApiReportEntity> findAll(org.springframework.data.domain.Sort sort) { return entities; }
        @Override public org.springframework.data.domain.Page<ApiReportEntity> findAll(org.springframework.data.domain.Pageable pageable) { return null; }
    }
}
