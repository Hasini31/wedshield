package com.webshield.findings;

import com.webshield.assessment.models.AssessmentResult;
import com.webshield.models.SecurityFinding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Deduplicates security assessment findings to prevent redundant alert fatigue.
 *
 * <p>Identifies duplicates based on:
 * <ul>
 *     <li>Website ID</li>
 *     <li>Affected URL (normalized)</li>
 *     <li>Affected Parameter (normalized, empty string if null)</li>
 *     <li>Vulnerability Category or Finding Name</li>
 * </ul>
 */
public class FindingDeduplicator {

    private static final Logger log = LoggerFactory.getLogger(FindingDeduplicator.class);

    /**
     * Deduplicates a collection of {@link SecurityFinding} items.
     * When identical findings match, the one with higher severity or richer evidence is retained.
     */
    public static List<SecurityFinding> deduplicate(Collection<SecurityFinding> findings) {
        if (findings == null || findings.isEmpty()) {
            return Collections.emptyList();
        }

        Map<String, SecurityFinding> uniqueMap = new LinkedHashMap<>();
        int duplicateCount = 0;

        for (SecurityFinding current : findings) {
            String key = buildDeduplicationKey(
                    current.getWebsiteId(),
                    current.getAffectedUrl(),
                    current.getAffectedParam(),
                    current.getCategory() != null ? current.getCategory() : current.getFindingName()
            );

            if (!uniqueMap.containsKey(key)) {
                uniqueMap.put(key, current);
            } else {
                duplicateCount++;
                SecurityFinding existing = uniqueMap.get(key);
                // Retain current if it has higher severity
                if (FindingClassifier.isHigherSeverity(current.getSeverity(), existing.getSeverity())) {
                    uniqueMap.put(key, current);
                }
            }
        }

        if (duplicateCount > 0) {
            log.info("Deduplication filter pruned {} redundant findings (kept {} unique).",
                    duplicateCount, uniqueMap.size());
        }

        return new ArrayList<>(uniqueMap.values());
    }

    /**
     * Deduplicates a list of {@link AssessmentResult} items for the assessment engine pipeline.
     */
    public static List<AssessmentResult> deduplicateResults(long websiteId, Collection<AssessmentResult> results) {
        if (results == null || results.isEmpty()) {
            return Collections.emptyList();
        }

        Map<String, AssessmentResult> uniqueMap = new LinkedHashMap<>();
        for (AssessmentResult ar : results) {
            String key = buildDeduplicationKey(
                    websiteId,
                    ar.getAffectedUrl(),
                    ar.getAffectedParam(),
                    ar.getCategory() != null ? ar.getCategory() : ar.getFindingName()
            );

            if (!uniqueMap.containsKey(key)) {
                uniqueMap.put(key, ar);
            }
        }
        return new ArrayList<>(uniqueMap.values());
    }

    /**
     * Constructs a normalized deduplication key.
     */
    public static String buildDeduplicationKey(long websiteId, String url, String param, String category) {
        String normUrl = url != null ? url.trim().toLowerCase() : "";
        String normParam = param != null ? param.trim().toLowerCase() : "";
        String normCat = category != null ? category.trim().toUpperCase() : "GENERAL";
        return websiteId + "::" + normUrl + "::" + normParam + "::" + normCat;
    }
}

