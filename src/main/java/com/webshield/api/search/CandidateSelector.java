package com.webshield.api.search;

import com.webshield.api.generation.ApiTestCase;
import com.webshield.api.models.ApiEndpoint;
import com.webshield.api.models.ParsedApiSpecification;
import com.webshield.api.mutation.MutationEngine;
import com.webshield.api.mutation.MutationResult;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * MIO-inspired candidate selector balancing exploration (fresh sampling) and exploitation
 * (focused mutation of candidates associated with less-explored objectives).
 */
public class CandidateSelector {

    private final SearchConfiguration config;
    private final Random random;
    private final MutationEngine mutationEngine;
    private final Map<String, AtomicInteger> objectiveSelectionCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> candidateSelectionCounts = new ConcurrentHashMap<>();

    public CandidateSelector(SearchConfiguration config, MutationEngine mutationEngine, Random random) {
        this.config = config != null ? config : SearchConfiguration.defaultConfig();
        this.mutationEngine = Objects.requireNonNull(mutationEngine, "mutationEngine must not be null");
        this.random = random != null ? random : new Random(this.config.getSeed());
    }

    /**
     * Represents the result of a selection step.
     */
    public record SelectionChoice(
            boolean isRandomSampling,
            SearchObjective selectedObjective,
            ApiTestCase parentCandidate,
            ApiTestCase candidateToEvaluate
    ) {}

    /**
     * Performs MIO selection: decides between random exploration and archive-based focused mutation.
     */
    public SelectionChoice selectNextCandidate(ObjectiveArchive archive, ParsedApiSpecification spec) {
        // 1. Probabilistic fresh random exploration (P_rnd)
        if (random.nextDouble() < config.getRandomSamplingProbability()) {
            return new SelectionChoice(true, null, null, null);
        }

        // 2. Archive-based exploitation: collect non-empty objective archives
        List<String> nonEmpties = new ArrayList<>();
        for (String objId : archive.getRegisteredObjectiveIds()) {
            if (!archive.getCandidates(objId).isEmpty()) {
                nonEmpties.add(objId);
            }
        }

        if (nonEmpties.isEmpty()) {
            // No archived candidates yet: must use random exploration
            return new SelectionChoice(true, null, null, null);
        }

        // 3. Select objective favoring less-explored objectives (Tournament selection)
        String chosenObjId = selectLessExploredObjective(nonEmpties);
        objectiveSelectionCounts.computeIfAbsent(chosenObjId, k -> new AtomicInteger(0)).incrementAndGet();

        SearchObjective objective = archive.getRegisteredObjectives().get(chosenObjId);
        List<ArchivedCandidate> candidates = archive.getCandidates(chosenObjId);

        // 4. Select candidate from archive favoring less-frequently selected items
        ArchivedCandidate chosenArchived = selectCandidateFromList(candidates);
        ApiTestCase parent = chosenArchived.testCase();
        candidateSelectionCounts.computeIfAbsent(parent.id(), k -> new AtomicInteger(0)).incrementAndGet();

        // 5. Mutate chosen candidate using MutationEngine
        ApiEndpoint endpoint = spec != null ? spec.findEndpoint(parent.path(), parent.method()).orElse(null) : null;
        List<MutationResult> mutations = mutationEngine.mutateTestCase(parent, endpoint);

        ApiTestCase mutatedCandidate;
        if (!mutations.isEmpty()) {
            int idx = random.nextInt(mutations.size());
            mutatedCandidate = mutations.get(idx).testCase();
        } else {
            // If mutation didn't produce a candidate (e.g. max depth), reuse parent with new seed
            mutatedCandidate = parent;
        }

        return new SelectionChoice(false, objective, parent, mutatedCandidate);
    }

    private String selectLessExploredObjective(List<String> objectiveIds) {
        if (objectiveIds.size() == 1) {
            return objectiveIds.get(0);
        }

        // 2-way tournament selection minimizing selection count
        int idx1 = random.nextInt(objectiveIds.size());
        int idx2 = random.nextInt(objectiveIds.size());
        String id1 = objectiveIds.get(idx1);
        String id2 = objectiveIds.get(idx2);

        int count1 = objectiveSelectionCounts.getOrDefault(id1, new AtomicInteger(0)).get();
        int count2 = objectiveSelectionCounts.getOrDefault(id2, new AtomicInteger(0)).get();

        return count1 <= count2 ? id1 : id2;
    }

    private ArchivedCandidate selectCandidateFromList(List<ArchivedCandidate> candidates) {
        if (candidates.size() == 1) {
            return candidates.get(0);
        }

        // Tournament between 2 candidates minimizing usage
        int idx1 = random.nextInt(candidates.size());
        int idx2 = random.nextInt(candidates.size());
        ArchivedCandidate c1 = candidates.get(idx1);
        ArchivedCandidate c2 = candidates.get(idx2);

        int count1 = candidateSelectionCounts.getOrDefault(c1.getCandidateId(), new AtomicInteger(0)).get();
        int count2 = candidateSelectionCounts.getOrDefault(c2.getCandidateId(), new AtomicInteger(0)).get();

        return count1 <= count2 ? c1 : c2;
    }

    public int getObjectiveSelectionCount(String objectiveId) {
        AtomicInteger count = objectiveSelectionCounts.get(objectiveId);
        return count != null ? count.get() : 0;
    }

    public int getCandidateSelectionCount(String candidateId) {
        AtomicInteger count = candidateSelectionCounts.get(candidateId);
        return count != null ? count.get() : 0;
    }
}

