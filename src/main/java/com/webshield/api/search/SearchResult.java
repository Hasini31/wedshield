package com.webshield.api.search;

import com.webshield.api.generation.ApiTestCase;

import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Immutable report summarizing the output, metrics, archive state, and best test candidates
 * discovered by the evolutionary search engine.
 */
public record SearchResult(
        int totalGenerations,
        int totalEvaluations,
        int totalObjectives,
        int objectivesAchieved,
        double objectiveCoverage,
        Map<String, Integer> archiveStatistics,
        List<ApiTestCase> bestCandidates,
        TerminationReason terminationReason,
        long searchDurationMs,
        long searchSeed
) implements Serializable {

    public SearchResult {
        archiveStatistics = archiveStatistics != null ? Collections.unmodifiableMap(new LinkedHashMap<>(archiveStatistics)) : Collections.emptyMap();
        bestCandidates = bestCandidates != null ? List.copyOf(bestCandidates) : List.of();
    }

    public boolean isFullyCovered() {
        return totalObjectives > 0 && objectivesAchieved >= totalObjectives;
    }

    public int getBestCandidatesCount() {
        return bestCandidates.size();
    }
}

