package com.webshield.findings;

import com.webshield.assessment.models.Severity;
import com.webshield.database.repositories.FindingRepository;
import com.webshield.models.SecurityFinding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import org.springframework.stereotype.Service;

/**
 * High-level business service managing vulnerability finding operations,
 * lifecycle status changes, deduplication, and aggregation.
 */
@Service
public class FindingService {

    private static final Logger log = LoggerFactory.getLogger(FindingService.class);

    private final FindingRepository repository;
    private final FindingHistoryService historyService;

    public FindingService() {
        this(new FindingRepository(), new FindingHistoryService());
    }

    public FindingService(FindingRepository repository, FindingHistoryService historyService) {
        this.repository = repository;
        this.historyService = historyService;
    }

    public List<SecurityFinding> getFindingsForUser(int userId) {
        if (userId <= 0) return Collections.emptyList();
        return repository.findSecurityFindingsByUserId(userId);
    }

    public List<SecurityFinding> getFindingsForScan(long scanId) {
        if (scanId <= 0) return Collections.emptyList();
        return repository.findSecurityFindingsByScanId(scanId);
    }

    public Optional<SecurityFinding> getFindingById(long findingId, int userId) {
        return repository.findSecurityFindingById(findingId, userId);
    }

    /**
     * Updates the review status of a finding (e.g. marking as FALSE_POSITIVE, RESOLVED, etc.)
     * and logs the transition in the finding audit trail.
     */
    public boolean updateFindingStatus(long findingId, FindingStatus newStatus, String username, String reason) {
        if (findingId <= 0 || newStatus == null) return false;

        boolean success = repository.updateFindingStatus(findingId, newStatus);
        if (success) {
            historyService.recordStatusChange(findingId, FindingStatus.OPEN, newStatus,
                    username != null ? username : "System", reason != null ? reason : "Status updated by analyst");
        }
        return success;
    }

    /**
     * Deduplicates findings using {@link FindingDeduplicator}.
     */
    public List<SecurityFinding> deduplicateFindings(Collection<SecurityFinding> findings) {
        return FindingDeduplicator.deduplicate(findings);
    }

    /**
     * Persists a deduplicated batch of security findings into the database.
     */
    public void persistScanFindings(long scanId, List<SecurityFinding> findings) {
        if (findings == null || findings.isEmpty()) return;
        List<SecurityFinding> deduplicated = FindingDeduplicator.deduplicate(findings);
        repository.insertFindingsBatch(scanId, deduplicated);
    }

    public Map<Severity, Long> getSeverityCountsForUser(int userId) {
        return repository.countFindingsBySeverity(userId);
    }

    public Map<Severity, Long> getSeverityCountsForScan(long scanId) {
        return repository.countFindingsBySeverityForScan(scanId);
    }

    public FindingHistoryService getHistoryService() {
        return historyService;
    }
}

