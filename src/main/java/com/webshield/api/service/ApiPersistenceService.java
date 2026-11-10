package com.webshield.api.service;

import com.webshield.api.analysis.ApiFindingSeverity;
import com.webshield.api.analysis.ApiSecurityFinding;
import com.webshield.api.analysis.RedactionUtils;
import com.webshield.api.dto.*;
import com.webshield.api.execution.ApiExecutionRequest;
import com.webshield.api.execution.ApiExecutionResponse;
import com.webshield.api.generation.ApiTestCase;
import com.webshield.api.models.ApiScanStatus;
import com.webshield.api.models.HttpMethod;
import com.webshield.api.repository.*;
import com.webshield.api.search.SearchResult;
import com.webshield.database.entities.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Core transactional persistence service for API security testing (Module H).
 * Enforces user ownership boundaries, applies secret redaction and body truncation,
 * manages scan lifecycles, and stores execution records, test cases, findings, and metrics.
 */
@Service
public class ApiPersistenceService {

    private static final Logger log = LoggerFactory.getLogger(ApiPersistenceService.class);
    public static final int MAX_STORED_BODY_LENGTH = 10000;

    private final ApiScanRepository scanRepository;
    private final ApiExecutionRepository executionRepository;
    private final ApiFindingRepository findingRepository;
    private final ApiTestCaseResultRepository testCaseResultRepository;
    private final ApiScanStatisticsRepository statisticsRepository;
    private final ApiProjectRepository apiProjectRepository;

    @Autowired
    public ApiPersistenceService(ApiScanRepository scanRepository,
                                 ApiExecutionRepository executionRepository,
                                 ApiFindingRepository findingRepository,
                                 ApiTestCaseResultRepository testCaseResultRepository,
                                 ApiScanStatisticsRepository statisticsRepository,
                                 ApiProjectRepository apiProjectRepository) {
        this.scanRepository = scanRepository;
        this.executionRepository = executionRepository;
        this.findingRepository = findingRepository;
        this.testCaseResultRepository = testCaseResultRepository;
        this.statisticsRepository = statisticsRepository;
        this.apiProjectRepository = apiProjectRepository;
    }

    // =========================================================================
    // 1. Scan Lifecycle Operations
    // =========================================================================

    @Transactional
    public ApiScanDto createScan(Long apiProjectId, Long userId, String scanName,
                                 String searchConfigSnapshot, String executionConfigSnapshot) {
        if (userId == null) throw new IllegalArgumentException("User ID must not be null");
        if (apiProjectId == null) throw new IllegalArgumentException("API Project ID must not be null");
        if (scanName == null || scanName.isBlank()) throw new IllegalArgumentException("Scan name must not be blank");

        // Validate project ownership if repository is present
        if (apiProjectRepository != null) {
            apiProjectRepository.findByIdAndUserId(apiProjectId, userId)
                    .orElseThrow(() -> new SecurityException("API project " + apiProjectId + " not found or access denied for user " + userId));
        }

        ApiScanEntity entity = new ApiScanEntity(apiProjectId, userId, scanName.trim());
        entity.setStatus(ApiScanStatus.PENDING);
        entity.setSearchConfigSnapshot(searchConfigSnapshot);
        entity.setExecutionConfigSnapshot(executionConfigSnapshot);
        entity.setStartedAt(LocalDateTime.now());

        ApiScanEntity saved = scanRepository.save(entity);
        log.info("Created API scan record id={} for project={} user={}", saved.getId(), apiProjectId, userId);
        return ApiPersistenceMapper.toDto(saved);
    }

    @Transactional
    public ApiScanDto updateScanStatus(Long scanId, Long userId, ApiScanStatus newStatus) {
        ApiScanEntity entity = getVerifiedScan(scanId, userId);
        entity.setStatus(newStatus != null ? newStatus : ApiScanStatus.PENDING);
        ApiScanEntity saved = scanRepository.save(entity);
        return ApiPersistenceMapper.toDto(saved);
    }

    @Transactional
    public ApiScanDto completeScan(Long scanId, Long userId, String terminationReason) {
        ApiScanEntity entity = getVerifiedScan(scanId, userId);
        entity.setStatus(ApiScanStatus.COMPLETED);
        entity.setCompletedAt(LocalDateTime.now());
        entity.setTerminationReason(terminationReason);
        if (entity.getStartedAt() != null) {
            entity.setDurationMs(Duration.between(entity.getStartedAt(), entity.getCompletedAt()).toMillis());
        }
        ApiScanEntity saved = scanRepository.save(entity);
        log.info("Completed API scan id={} for user={}", scanId, userId);
        return ApiPersistenceMapper.toDto(saved);
    }

    @Transactional
    public ApiScanDto failScan(Long scanId, Long userId, String errorMessage) {
        ApiScanEntity entity = getVerifiedScan(scanId, userId);
        entity.setStatus(ApiScanStatus.FAILED);
        entity.setCompletedAt(LocalDateTime.now());
        entity.setErrorMessage(errorMessage);
        if (entity.getStartedAt() != null) {
            entity.setDurationMs(Duration.between(entity.getStartedAt(), entity.getCompletedAt()).toMillis());
        }
        ApiScanEntity saved = scanRepository.save(entity);
        log.warn("API scan id={} failed: {}", scanId, errorMessage);
        return ApiPersistenceMapper.toDto(saved);
    }

    @Transactional
    public ApiScanDto cancelScan(Long scanId, Long userId, String terminationReason) {
        ApiScanEntity entity = getVerifiedScan(scanId, userId);
        entity.setStatus(ApiScanStatus.CANCELLED);
        entity.setCompletedAt(LocalDateTime.now());
        entity.setTerminationReason(terminationReason != null ? terminationReason : "USER_CANCELLED");
        if (entity.getStartedAt() != null) {
            entity.setDurationMs(Duration.between(entity.getStartedAt(), entity.getCompletedAt()).toMillis());
        }
        ApiScanEntity saved = scanRepository.save(entity);
        log.info("Cancelled API scan id={} for user={}", scanId, userId);
        return ApiPersistenceMapper.toDto(saved);
    }

    // =========================================================================
    // 2. Execution Results Persistence (Module F Integration)
    // =========================================================================

    @Transactional
    public ApiExecutionDto saveExecution(Long scanId, Long userId, ApiExecutionResponse response, String endpoint, HttpMethod method) {
        ApiScanEntity scan = getVerifiedScan(scanId, userId);
        if (response == null) throw new IllegalArgumentException("Execution response must not be null");

        boolean[] flags = new boolean[2]; // [0]=truncated, [1]=binary
        String sanitizedBody = sanitizeResponseBody(response.responseBody(), response.contentType(), flags);
        String sanitizedHeaders = sanitizeHeaders(response.responseHeaders());

        ApiExecutionEntity exec = new ApiExecutionEntity();
        exec.setScanId(scan.getId());
        exec.setExecutionUuid(response.executionId());
        exec.setTestCaseId(response.testCaseId());
        exec.setEndpoint(endpoint != null ? endpoint : "/");
        exec.setHttpMethod(method != null ? method.name() : "GET");
        exec.setOutcome(response.outcome() != null ? response.outcome().name() : "UNKNOWN");
        exec.setStatusCode(response.statusCode());
        exec.setResponseTimeMs(response.responseTimeMs());
        exec.setResponseSizeBytes(response.responseSizeBytes());
        exec.setResponseHeaders(sanitizedHeaders);
        exec.setResponseBody(sanitizedBody);
        exec.setBodyTruncated(flags[0]);
        exec.setBinaryResponse(flags[1]);
        exec.setErrorMessage(response.errorMessage());
        exec.setExecutedAt(LocalDateTime.now());

        ApiExecutionEntity saved = executionRepository.save(exec);

        // Update scan total executions count
        scan.setTotalExecutedRequests(scan.getTotalExecutedRequests() + 1);
        scanRepository.save(scan);

        return ApiPersistenceMapper.toDto(saved);
    }

    @Transactional
    public List<ApiExecutionDto> saveExecutionsBatch(Long scanId, Long userId, List<ExecutionPayload> payloads) {
        ApiScanEntity scan = getVerifiedScan(scanId, userId);
        if (payloads == null || payloads.isEmpty()) return Collections.emptyList();

        List<ApiExecutionEntity> entities = new ArrayList<>();
        for (ExecutionPayload p : payloads) {
            if (p == null || p.response() == null) continue;
            ApiExecutionResponse res = p.response();

            boolean[] flags = new boolean[2];
            String sanitizedBody = sanitizeResponseBody(res.responseBody(), res.contentType(), flags);
            String sanitizedHeaders = sanitizeHeaders(res.responseHeaders());

            ApiExecutionEntity exec = new ApiExecutionEntity();
            exec.setScanId(scan.getId());
            exec.setExecutionUuid(res.executionId());
            exec.setTestCaseId(res.testCaseId());
            exec.setEndpoint(p.endpoint() != null ? p.endpoint() : "/");
            exec.setHttpMethod(p.method() != null ? p.method().name() : "GET");
            exec.setOutcome(res.outcome() != null ? res.outcome().name() : "UNKNOWN");
            exec.setStatusCode(res.statusCode());
            exec.setResponseTimeMs(res.responseTimeMs());
            exec.setResponseSizeBytes(res.responseSizeBytes());
            exec.setResponseHeaders(sanitizedHeaders);
            exec.setResponseBody(sanitizedBody);
            exec.setBodyTruncated(flags[0]);
            exec.setBinaryResponse(flags[1]);
            exec.setErrorMessage(res.errorMessage());
            exec.setExecutedAt(LocalDateTime.now());
            entities.add(exec);
        }

        List<ApiExecutionEntity> saved = executionRepository.saveAll(entities);
        scan.setTotalExecutedRequests(scan.getTotalExecutedRequests() + saved.size());
        scanRepository.save(scan);

        return ApiPersistenceMapper.toExecutionDtos(saved);
    }

    // =========================================================================
    // 3. Security Findings Persistence (Module G Integration)
    // =========================================================================

    @Transactional
    public List<ApiFindingDto> saveFindings(Long scanId, Long userId, Long apiProjectId, List<ApiSecurityFinding> findings) {
        ApiScanEntity scan = getVerifiedScan(scanId, userId);
        if (findings == null || findings.isEmpty()) return Collections.emptyList();

        List<ApiFindingEntity> toSave = new ArrayList<>();
        Set<String> seenKeys = new HashSet<>();

        int critical = 0, high = 0, medium = 0, low = 0, info = 0;

        for (ApiSecurityFinding f : findings) {
            if (f == null) continue;

            // Preserve deduplication within the scan
            String dedupKey = f.getDeduplicationKey();
            if (seenKeys.contains(dedupKey)) {
                continue;
            }
            seenKeys.add(dedupKey);

            ApiFindingEntity fe = new ApiFindingEntity();
            fe.setScanId(scan.getId());
            fe.setApiProjectId(apiProjectId != null ? apiProjectId : scan.getApiProjectId());
            fe.setFindingUuid(f.findingId());
            fe.setExecutionUuid(f.executionId());
            fe.setRuleId(f.ruleId());
            fe.setTitle(f.title());
            fe.setDescription(f.description());
            fe.setSeverity(f.severity().name());
            fe.setConfidence(f.confidence().name());
            fe.setHttpMethod(f.httpMethod() != null ? f.httpMethod().name() : "GET");
            fe.setEndpointPath(f.endpointPath());
            fe.setParameterOrField(f.parameterOrField());
            fe.setEvidence(RedactionUtils.redactSensitiveData(f.evidence()));
            fe.setCweId(f.cweId());
            fe.setOwaspCategory(f.owaspCategory() != null ? f.owaspCategory().getCode() : "");
            fe.setRemediation(f.remediation());
            fe.setConfirmed(f.isConfirmed());
            fe.setLifecycleStatus("ACTIVE");
            fe.setDetectedAt(LocalDateTime.now());

            toSave.add(fe);

            // Tally severity counters
            switch (f.severity()) {
                case CRITICAL -> critical++;
                case HIGH -> high++;
                case MEDIUM -> medium++;
                case LOW -> low++;
                case INFORMATIONAL -> info++;
            }
        }

        List<ApiFindingEntity> saved = findingRepository.saveAll(toSave);

        // Update scan summary statistics
        scan.setCriticalCount(scan.getCriticalCount() + critical);
        scan.setHighCount(scan.getHighCount() + high);
        scan.setMediumCount(scan.getMediumCount() + medium);
        scan.setLowCount(scan.getLowCount() + low);
        scan.setInformationalCount(scan.getInformationalCount() + info);
        scan.setTotalFindings(scan.getTotalFindings() + saved.size());
        scanRepository.save(scan);

        log.info("Persisted {} findings for scan id={}", saved.size(), scanId);
        return ApiPersistenceMapper.toFindingDtos(saved);
    }

    // =========================================================================
    // 4. Test Case Lineage Persistence (Module C, D, E Integration)
    // =========================================================================

    @Transactional
    public List<ApiTestCaseResultDto> saveTestCaseResults(Long scanId, Long userId, List<ApiTestCase> testCases) {
        ApiScanEntity scan = getVerifiedScan(scanId, userId);
        if (testCases == null || testCases.isEmpty()) return Collections.emptyList();

        List<ApiTestCaseResultEntity> entities = new ArrayList<>();
        for (ApiTestCase tc : testCases) {
            if (tc == null) continue;
            ApiTestCaseResultEntity te = new ApiTestCaseResultEntity();
            te.setScanId(scan.getId());
            te.setTestCaseId(tc.id());
            te.setEndpointIdentifier(tc.endpointIdentifier() != null ? tc.endpointIdentifier() : "");
            te.setHttpMethod(tc.method() != null ? tc.method().name() : "GET");
            te.setCategory(tc.category() != null ? tc.category().name() : "VALID");
            te.setStrategy(tc.strategy() != null ? tc.strategy().name() : "UNKNOWN");
            te.setParentTestCaseId(tc.parentTestCaseId());
            te.setTargetedProperty(tc.targetedProperty());
            te.setTargetedConstraint(tc.targetedConstraint());
            te.setDescription(tc.description());
            te.setCreatedAt(LocalDateTime.now());
            entities.add(te);
        }

        List<ApiTestCaseResultEntity> saved = testCaseResultRepository.saveAll(entities);
        scan.setTotalGeneratedTestCases(scan.getTotalGeneratedTestCases() + saved.size());
        scanRepository.save(scan);

        return ApiPersistenceMapper.toTestCaseDtos(saved);
    }

    // =========================================================================
    // 5. Scan Statistics Calculation & Persistence
    // =========================================================================

    @Transactional
    public ApiScanStatisticsDto calculateAndSaveStatistics(Long scanId, Long userId, SearchResult searchResult) {
        ApiScanEntity scan = getVerifiedScan(scanId, userId);

        List<ApiExecutionEntity> executions = executionRepository.findByScanIdOrderByExecutedAtAsc(scanId);

        double totalMs = 0;
        long minMs = executions.isEmpty() ? 0 : Long.MAX_VALUE;
        long maxMs = 0;
        long totalBytes = 0;
        int count2xx = 0;
        int count4xx = 0;
        int count5xx = 0;
        int errorOutcomes = 0;

        for (ApiExecutionEntity ex : executions) {
            long rt = ex.getResponseTimeMs();
            totalMs += rt;
            if (rt < minMs) minMs = rt;
            if (rt > maxMs) maxMs = rt;
            totalBytes += ex.getResponseSizeBytes();

            int code = ex.getStatusCode();
            if (code >= 200 && code < 300) count2xx++;
            else if (code >= 400 && code < 500) count4xx++;
            else if (code >= 500 && code < 600) count5xx++;

            if (!"SUCCESS".equalsIgnoreCase(ex.getOutcome())) {
                errorOutcomes++;
            }
        }

        if (minMs == Long.MAX_VALUE) minMs = 0;
        double avgMs = executions.isEmpty() ? 0.0 : totalMs / executions.size();

        ApiScanStatisticsEntity stats = statisticsRepository.findByScanId(scanId)
                .orElse(new ApiScanStatisticsEntity(scanId));

        stats.setAvgResponseTimeMs(Math.round(avgMs * 100.0) / 100.0);
        stats.setMinResponseTimeMs(minMs);
        stats.setMaxResponseTimeMs(maxMs);
        stats.setTotalDataTransferredBytes(totalBytes);
        stats.setStatus2xxCount(count2xx);
        stats.setStatus4xxCount(count4xx);
        stats.setStatus5xxCount(count5xx);
        stats.setErrorOutcomesCount(errorOutcomes);

        if (searchResult != null) {
            stats.setObjectivesAchieved(searchResult.objectivesAchieved());
            stats.setTotalObjectives(searchResult.totalObjectives());
            stats.setCoveragePercentage(searchResult.objectiveCoverage());
        }

        stats.setCalculatedAt(LocalDateTime.now());
        ApiScanStatisticsEntity saved = statisticsRepository.save(stats);
        return ApiPersistenceMapper.toDto(saved);
    }

    // =========================================================================
    // 6. Query and Retrieval Services (Strict User-Ownership Enforced)
    // =========================================================================

    @Transactional(readOnly = true)
    public List<ApiScanDto> getScansForUser(Long userId) {
        if (userId == null) return Collections.emptyList();
        return ApiPersistenceMapper.toScanDtos(scanRepository.findByUserIdOrderByCreatedAtDesc(userId));
    }

    @Transactional(readOnly = true)
    public Page<ApiScanDto> getScansForUser(Long userId, Pageable pageable) {
        if (userId == null) return Page.empty();
        return scanRepository.findByUserIdOrderByCreatedAtDesc(userId, pageable)
                .map(ApiPersistenceMapper::toDto);
    }

    @Transactional(readOnly = true)
    public Optional<ApiScanDto> getScanById(Long scanId, Long userId) {
        if (scanId == null || userId == null) return Optional.empty();
        return scanRepository.findByIdAndUserId(scanId, userId)
                .map(ApiPersistenceMapper::toDto);
    }

    @Transactional(readOnly = true)
    public List<ApiScanDto> getScansForProject(Long apiProjectId, Long userId) {
        if (apiProjectId == null || userId == null) return Collections.emptyList();
        return ApiPersistenceMapper.toScanDtos(scanRepository.findByApiProjectIdAndUserIdOrderByCreatedAtDesc(apiProjectId, userId));
    }

    @Transactional(readOnly = true)
    public Page<ApiExecutionDto> getExecutionsForScan(Long scanId, Long userId, Pageable pageable) {
        getVerifiedScan(scanId, userId);
        return executionRepository.findByScanIdOrderByExecutedAtAsc(scanId, pageable)
                .map(ApiPersistenceMapper::toDto);
    }

    @Transactional(readOnly = true)
    public List<ApiExecutionDto> getExecutionsForScan(Long scanId, Long userId) {
        getVerifiedScan(scanId, userId);
        return ApiPersistenceMapper.toExecutionDtos(executionRepository.findByScanIdOrderByExecutedAtAsc(scanId));
    }

    @Transactional(readOnly = true)
    public Page<ApiFindingDto> getFindingsForScan(Long scanId, Long userId, Pageable pageable) {
        getVerifiedScan(scanId, userId);
        return findingRepository.findByScanIdOrderByDetectedAtAsc(scanId, pageable)
                .map(ApiPersistenceMapper::toDto);
    }

    @Transactional(readOnly = true)
    public List<ApiFindingDto> getFindingsForScan(Long scanId, Long userId) {
        getVerifiedScan(scanId, userId);
        return ApiPersistenceMapper.toFindingDtos(findingRepository.findByScanIdOrderByDetectedAtAsc(scanId));
    }

    @Transactional(readOnly = true)
    public List<ApiTestCaseResultDto> getTestCasesForScan(Long scanId, Long userId) {
        getVerifiedScan(scanId, userId);
        return ApiPersistenceMapper.toTestCaseDtos(testCaseResultRepository.findByScanIdOrderByCreatedAtAsc(scanId));
    }

    @Transactional(readOnly = true)
    public Page<ApiTestCaseResultDto> getTestCasesForScan(Long scanId, Long userId, Pageable pageable) {
        getVerifiedScan(scanId, userId);
        return testCaseResultRepository.findByScanIdOrderByCreatedAtAsc(scanId, pageable)
                .map(ApiPersistenceMapper::toDto);
    }

    @Transactional
    public void deleteScan(Long scanId, Long userId) {
        ApiScanEntity scan = getVerifiedScan(scanId, userId);
        executionRepository.deleteAll(executionRepository.findByScanIdOrderByExecutedAtAsc(scanId));
        findingRepository.deleteAll(findingRepository.findByScanIdOrderByDetectedAtAsc(scanId));
        testCaseResultRepository.deleteAll(testCaseResultRepository.findByScanIdOrderByCreatedAtAsc(scanId));
        statisticsRepository.findByScanId(scanId).ifPresent(statisticsRepository::delete);
        scanRepository.delete(scan);
        log.info("Deleted API scan id={} for user={}", scanId, userId);
    }

    @Transactional(readOnly = true)
    public List<ApiFindingDto> getFindingsBySeverity(Long scanId, Long userId, String severity) {
        getVerifiedScan(scanId, userId);
        return ApiPersistenceMapper.toFindingDtos(findingRepository.findByScanIdAndSeverity(scanId, severity));
    }

    @Transactional(readOnly = true)
    public List<ApiFindingDto> getFindingsByRule(Long scanId, Long userId, String ruleId) {
        getVerifiedScan(scanId, userId);
        return ApiPersistenceMapper.toFindingDtos(findingRepository.findByScanIdAndRuleId(scanId, ruleId));
    }

    @Transactional(readOnly = true)
    public List<ApiFindingDto> searchFindingsByEndpoint(Long scanId, Long userId, String endpointQuery) {
        getVerifiedScan(scanId, userId);
        return ApiPersistenceMapper.toFindingDtos(findingRepository.findByScanIdAndEndpointPathContaining(scanId, endpointQuery));
    }

    @Transactional(readOnly = true)
    public Optional<ApiScanStatisticsDto> getScanStatistics(Long scanId, Long userId) {
        getVerifiedScan(scanId, userId);
        return statisticsRepository.findByScanId(scanId).map(ApiPersistenceMapper::toDto);
    }

    @Transactional(readOnly = true)
    public ApiScanComparisonDto compareScans(Long scanIdA, Long scanIdB, Long userId) {
        ApiScanDto scanA = getScanById(scanIdA, userId)
                .orElseThrow(() -> new SecurityException("Scan A " + scanIdA + " not accessible"));
        ApiScanDto scanB = getScanById(scanIdB, userId)
                .orElseThrow(() -> new SecurityException("Scan B " + scanIdB + " not accessible"));

        List<ApiFindingDto> findingsA = ApiPersistenceMapper.toFindingDtos(findingRepository.findByScanIdOrderByDetectedAtAsc(scanIdA));
        List<ApiFindingDto> findingsB = ApiPersistenceMapper.toFindingDtos(findingRepository.findByScanIdOrderByDetectedAtAsc(scanIdB));

        Set<String> keysA = findingsA.stream().map(this::getFindingComparisonFingerprint).collect(Collectors.toSet());
        Set<String> keysB = findingsB.stream().map(this::getFindingComparisonFingerprint).collect(Collectors.toSet());

        List<ApiFindingDto> newFindings = findingsB.stream()
                .filter(fb -> !keysA.contains(getFindingComparisonFingerprint(fb)))
                .toList();

        List<ApiFindingDto> resolvedFindings = findingsA.stream()
                .filter(fa -> !keysB.contains(getFindingComparisonFingerprint(fa)))
                .toList();

        List<ApiFindingDto> persistentFindings = findingsB.stream()
                .filter(fb -> keysA.contains(getFindingComparisonFingerprint(fb)))
                .toList();

        int persistent = persistentFindings.size();

        long durDiff = scanB.durationMs() - scanA.durationMs();

        Optional<ApiScanStatisticsDto> statsA = statisticsRepository.findByScanId(scanIdA).map(ApiPersistenceMapper::toDto);
        Optional<ApiScanStatisticsDto> statsB = statisticsRepository.findByScanId(scanIdB).map(ApiPersistenceMapper::toDto);
        double covDiff = (statsB.map(ApiScanStatisticsDto::coveragePercentage).orElse(0.0)) -
                (statsA.map(ApiScanStatisticsDto::coveragePercentage).orElse(0.0));

        return new ApiScanComparisonDto(
                scanA,
                scanB,
                newFindings.size(),
                resolvedFindings.size(),
                persistent,
                covDiff,
                durDiff,
                newFindings,
                resolvedFindings,
                persistentFindings
        );
    }

    private String getFindingComparisonFingerprint(ApiFindingDto f) {
        if (f == null) return "";
        String rule = f.ruleId() != null && !f.ruleId().isBlank() ? f.ruleId().trim() : (f.title() != null ? f.title().trim() : "");
        String method = f.httpMethod() != null ? f.httpMethod().trim().toUpperCase() : "GET";
        String endpoint = f.endpointPath() != null ? f.endpointPath().trim().toLowerCase() : "";
        if (endpoint.endsWith("/") && endpoint.length() > 1) {
            endpoint = endpoint.substring(0, endpoint.length() - 1);
        }
        String param = f.parameterOrField() != null ? f.parameterOrField().trim().toLowerCase() : "";
        return rule + "|" + method + "|" + endpoint + "|" + param;
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    private ApiScanEntity getVerifiedScan(Long scanId, Long userId) {
        if (scanId == null) throw new IllegalArgumentException("Scan ID must not be null");
        if (userId == null) throw new IllegalArgumentException("User ID must not be null");

        ApiScanEntity scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new NoSuchElementException("API scan not found: " + scanId));

        if (!Objects.equals(scan.getUserId(), userId)) {
            log.warn("Access denied: User {} attempted to access Scan {} owned by User {}", userId, scanId, scan.getUserId());
            throw new SecurityException("Access denied: User does not own scan " + scanId);
        }

        return scan;
    }

    private String sanitizeResponseBody(String rawBody, String contentType, boolean[] outFlags) {
        if (rawBody == null || rawBody.isBlank()) {
            return "";
        }
        if (contentType != null && (contentType.contains("octet-stream")
                || contentType.contains("image/")
                || contentType.contains("audio/")
                || contentType.contains("video/"))) {
            outFlags[1] = true;
            return "[BINARY DATA - " + rawBody.length() + " BYTES]";
        }

        String redacted = RedactionUtils.redactSensitiveData(rawBody);
        if (redacted.length() > MAX_STORED_BODY_LENGTH) {
            outFlags[0] = true;
            return redacted.substring(0, MAX_STORED_BODY_LENGTH) + "\n... [TRUNCATED: original size " + rawBody.length() + " bytes]";
        }
        return redacted;
    }

    private String sanitizeHeaders(Map<String, List<String>> headers) {
        if (headers == null || headers.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            String k = entry.getKey();
            List<String> vals = entry.getValue();
            if (vals != null) {
                for (String v : vals) {
                    String line = k + ": " + v;
                    sb.append(RedactionUtils.redactSensitiveData(line)).append("\n");
                }
            }
        }
        return sb.toString().trim();
    }

    public record ExecutionPayload(ApiExecutionResponse response, String endpoint, HttpMethod method) {}
}

