package com.webshield.api.search;

import com.webshield.api.generation.ApiTestCase;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Multi-objective archive maintaining top-performing test candidates per independent objective.
 * Enforces per-objective capacity limits, duplicate suppression, and replacement of inferior candidates.
 */
public class ObjectiveArchive {

    private final int maxArchiveSizePerObjective;
    private final Map<String, List<ArchivedCandidate>> archives = new ConcurrentHashMap<>();
    private final Map<String, SearchObjective> registeredObjectives = new ConcurrentHashMap<>();

    public ObjectiveArchive(int maxArchiveSizePerObjective) {
        this.maxArchiveSizePerObjective = Math.max(1, maxArchiveSizePerObjective);
    }

    public void registerObjective(SearchObjective objective) {
        if (objective != null) {
            registeredObjectives.put(objective.getId(), objective);
            archives.computeIfAbsent(objective.getId(), k -> Collections.synchronizedList(new ArrayList<>()));
        }
    }

    public void registerObjectives(Collection<SearchObjective> objectives) {
        if (objectives != null) {
            objectives.forEach(this::registerObjective);
        }
    }

    /**
     * Attempts to store or update a candidate in the objective's archive.
     * Returns true if the candidate was added or replaced an inferior candidate.
     */
    public boolean offer(SearchObjective objective, ApiTestCase candidate, EvaluationResult execution, FitnessScore score, int generation) {
        if (objective == null || candidate == null || score == null || score.isUnusable() || score.isExecutionFailure()) {
            return false;
        }

        registerObjective(objective);
        List<ArchivedCandidate> archive = archives.get(objective.getId());

        synchronized (archive) {
            // Check duplicate candidate by ID or exact signature
            for (ArchivedCandidate existing : archive) {
                if (existing.getCandidateId().equals(candidate.id())) {
                    if (score.isBetterThan(existing.fitness())) {
                        archive.remove(existing);
                        archive.add(new ArchivedCandidate(candidate, execution, score, generation));
                        sortArchive(archive);
                        return true;
                    }
                    return false;
                }
            }

            // If archive has space, append and sort
            if (archive.size() < maxArchiveSizePerObjective) {
                archive.add(new ArchivedCandidate(candidate, execution, score, generation));
                sortArchive(archive);
                return true;
            }

            // Archive is at capacity: check if candidate is better than the worst
            ArchivedCandidate worst = archive.get(archive.size() - 1);
            if (score.isBetterThan(worst.fitness())) {
                archive.remove(archive.size() - 1);
                archive.add(new ArchivedCandidate(candidate, execution, score, generation));
                sortArchive(archive);
                return true;
            }

            return false;
        }
    }

    private void sortArchive(List<ArchivedCandidate> list) {
        list.sort((a, b) -> {
            // Best score first
            if (a.fitness().isBetterThan(b.fitness())) return -1;
            if (b.fitness().isBetterThan(a.fitness())) return 1;
            return 0;
        });
    }

    public boolean isObjectiveAchieved(String objectiveId) {
        List<ArchivedCandidate> list = archives.get(objectiveId);
        if (list == null || list.isEmpty()) return false;
        synchronized (list) {
            return list.stream().anyMatch(ArchivedCandidate::isAchieved);
        }
    }

    public Set<String> getCoveredObjectiveIds() {
        Set<String> set = new LinkedHashSet<>();
        for (Map.Entry<String, List<ArchivedCandidate>> entry : archives.entrySet()) {
            List<ArchivedCandidate> list = entry.getValue();
            synchronized (list) {
                if (list.stream().anyMatch(ArchivedCandidate::isAchieved)) {
                    set.add(entry.getKey());
                }
            }
        }
        return Collections.unmodifiableSet(set);
    }

    public double getCoverageRatio() {
        if (registeredObjectives.isEmpty()) return 0.0;
        return (double) getCoveredObjectiveIds().size() / registeredObjectives.size();
    }

    public Optional<ArchivedCandidate> getBestCandidate(String objectiveId) {
        List<ArchivedCandidate> list = archives.get(objectiveId);
        if (list == null || list.isEmpty()) return Optional.empty();
        synchronized (list) {
            return Optional.of(list.get(0));
        }
    }

    public List<ArchivedCandidate> getCandidates(String objectiveId) {
        List<ArchivedCandidate> list = archives.get(objectiveId);
        if (list == null || list.isEmpty()) return List.of();
        synchronized (list) {
            return List.copyOf(list);
        }
    }

    public List<ApiTestCase> getAllBestCandidates() {
        Map<String, ApiTestCase> bestMap = new LinkedHashMap<>();
        for (String objId : registeredObjectives.keySet()) {
            getBestCandidate(objId).ifPresent(c -> bestMap.put(c.getCandidateId(), c.testCase()));
        }
        return new ArrayList<>(bestMap.values());
    }

    public int getTotalArchivedCandidatesCount() {
        int count = 0;
        for (List<ArchivedCandidate> list : archives.values()) {
            synchronized (list) {
                count += list.size();
            }
        }
        return count;
    }

    public Map<String, Integer> getArchiveSizes() {
        Map<String, Integer> map = new LinkedHashMap<>();
        for (Map.Entry<String, List<ArchivedCandidate>> entry : archives.entrySet()) {
            map.put(entry.getKey(), entry.getValue().size());
        }
        return Collections.unmodifiableMap(map);
    }

    public Set<String> getRegisteredObjectiveIds() {
        return Collections.unmodifiableSet(registeredObjectives.keySet());
    }

    public Map<String, SearchObjective> getRegisteredObjectives() {
        return Collections.unmodifiableMap(registeredObjectives);
    }

    public int getMaxArchiveSizePerObjective() {
        return maxArchiveSizePerObjective;
    }
}

