package com.webshield.findings;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;

/**
 * Service tracking finding status history, auditing state changes and analyst notes.
 */
@Service
public class FindingHistoryService {

    private static final Logger log = LoggerFactory.getLogger(FindingHistoryService.class);

    public record FindingHistoryEntry(
            long findingId,
            FindingStatus previousStatus,
            FindingStatus newStatus,
            String changedBy,
            String reason,
            LocalDateTime timestamp
    ) {}

    private final Map<Long, List<FindingHistoryEntry>> historyMap = new ConcurrentHashMap<>();

    /**
     * Records a status transition for a finding.
     */
    public void recordStatusChange(long findingId, FindingStatus oldStatus, FindingStatus newStatus,
                                   String user, String reason) {
        FindingHistoryEntry entry = new FindingHistoryEntry(
                findingId, oldStatus, newStatus, user, reason, LocalDateTime.now()
        );
        historyMap.computeIfAbsent(findingId, k -> new ArrayList<>()).add(entry);
        log.info("Finding ID={} transitioned from {} to {} by user '{}' (Reason: {})",
                findingId, oldStatus, newStatus, user, reason);
    }

    /**
     * Retrieves the audit history entries for a given finding.
     */
    public List<FindingHistoryEntry> getHistory(long findingId) {
        return historyMap.getOrDefault(findingId, Collections.emptyList());
    }

    public void clearHistory(long findingId) {
        historyMap.remove(findingId);
    }
}

