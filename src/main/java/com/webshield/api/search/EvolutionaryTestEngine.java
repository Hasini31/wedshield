package com.webshield.api.search;

import com.webshield.api.generation.ApiTestCase;
import com.webshield.api.generation.ApiTestGenerator;
import com.webshield.api.models.ApiEndpoint;
import com.webshield.api.models.ApiParameter;
import com.webshield.api.models.ApiSchema;
import com.webshield.api.models.ParsedApiSpecification;
import com.webshield.api.mutation.MutationEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Evolutionary API Test Generation Engine inspired by the Many Independent Objective (MIO) algorithm.
 * Coordinates objective discovery, candidate evaluation, archive retention, and mutation-driven exploration.
 */
@Service
public class EvolutionaryTestEngine {

    private static final Logger log = LoggerFactory.getLogger(EvolutionaryTestEngine.class);

    private final ApiTestGenerator testGenerator;
    private final MutationEngine mutationEngine;
    private final FitnessEvaluator fitnessEvaluator;

    public EvolutionaryTestEngine(ApiTestGenerator testGenerator, MutationEngine mutationEngine) {
        this.testGenerator = Objects.requireNonNull(testGenerator, "testGenerator must not be null");
        this.mutationEngine = Objects.requireNonNull(mutationEngine, "mutationEngine must not be null");
        this.fitnessEvaluator = new FitnessEvaluator();
    }

    public SearchResult search(ParsedApiSpecification spec) {
        return search(spec, new MockCandidateEvaluator(), SearchConfiguration.defaultConfig(), null);
    }

    public SearchResult search(ParsedApiSpecification spec, CandidateEvaluator evaluator) {
        return search(spec, evaluator, SearchConfiguration.defaultConfig(), null);
    }

    public SearchResult search(ParsedApiSpecification spec, CandidateEvaluator evaluator, SearchConfiguration config) {
        return search(spec, evaluator, config, null);
    }

    /**
     * Executes the generational evolutionary search workflow.
     */
    public SearchResult search(ParsedApiSpecification spec, CandidateEvaluator evaluator,
                               SearchConfiguration config, SearchProgress customProgress) {
        long startTime = System.currentTimeMillis();
        SearchConfiguration activeConfig = config != null ? config : SearchConfiguration.defaultConfig();
        CandidateEvaluator activeEvaluator = evaluator != null ? evaluator : new MockCandidateEvaluator();
        SearchProgress progress = customProgress != null
                ? customProgress
                : new SearchProgress(activeConfig.getEvaluationBudget(), activeConfig.getMaxGenerations());

        progress.setStatus(SearchStatus.INITIALIZING);

        if (spec == null || spec.getEndpoints().isEmpty()) {
            progress.setStatus(SearchStatus.COMPLETED);
            return new SearchResult(0, 0, 0, 0, 0.0, Map.of(), List.of(),
                    TerminationReason.NO_CANDIDATES_GENERATED, System.currentTimeMillis() - startTime, activeConfig.getSeed());
        }

        // 1. Initialize Independent Testing Objectives
        ObjectiveArchive archive = new ObjectiveArchive(activeConfig.getMaxArchiveSizePerObjective());
        List<SearchObjective> objectives = extractObjectives(spec);
        archive.registerObjectives(objectives);

        log.info("Initialized {} independent objectives across {} endpoints", objectives.size(), spec.getEndpointsCount());

        Random random = new Random(activeConfig.getSeed());
        CandidateSelector selector = new CandidateSelector(activeConfig, mutationEngine, random);

        // 2. Initial Candidate Generation (Module C)
        progress.setStatus(SearchStatus.RUNNING);
        List<ApiTestCase> initialCandidates = testGenerator.generateSuite(spec);

        if (initialCandidates.isEmpty()) {
            progress.setStatus(SearchStatus.COMPLETED);
            return new SearchResult(0, 0, objectives.size(), 0, 0.0, Map.of(), List.of(),
                    TerminationReason.NO_CANDIDATES_GENERATED, System.currentTimeMillis() - startTime, activeConfig.getSeed());
        }

        // 3. Evaluate Initial Candidates
        for (ApiTestCase candidate : initialCandidates) {
            if (progress.isCancelled() || progress.getEvaluationsCompleted() >= activeConfig.getEvaluationBudget()) {
                break;
            }

            EvaluationResult evalRes = safeEvaluate(activeEvaluator, candidate);
            progress.incrementEvaluations();

            for (SearchObjective obj : archive.getRegisteredObjectives().values()) {
                FitnessScore score = fitnessEvaluator.evaluate(obj, candidate, evalRes);
                archive.offer(obj, candidate, evalRes, score, 0);
            }
            progress.updateProgress(archive.getCoveredObjectiveIds().size(), archive.getCoverageRatio());
        }

        // 4. Generational Evolution Loop
        while (progress.getCurrentGeneration() < activeConfig.getMaxGenerations()
                && progress.getEvaluationsCompleted() < activeConfig.getEvaluationBudget()
                && !progress.isCancelled()
                && archive.getCoverageRatio() < activeConfig.getTargetObjectiveCoverage()) {

            int gen = progress.incrementGeneration();

            for (int i = 0; i < activeConfig.getPopulationSize(); i++) {
                if (progress.getEvaluationsCompleted() >= activeConfig.getEvaluationBudget() || progress.isCancelled()) {
                    break;
                }

                CandidateSelector.SelectionChoice choice = selector.selectNextCandidate(archive, spec);
                ApiTestCase candidateToTest;

                if (choice.isRandomSampling() || choice.candidateToEvaluate() == null) {
                    // Random exploration
                    candidateToTest = initialCandidates.get(random.nextInt(initialCandidates.size()));
                } else {
                    // Focused mutation
                    candidateToTest = choice.candidateToEvaluate();
                }

                EvaluationResult evalRes = safeEvaluate(activeEvaluator, candidateToTest);
                progress.incrementEvaluations();

                for (SearchObjective obj : archive.getRegisteredObjectives().values()) {
                    FitnessScore score = fitnessEvaluator.evaluate(obj, candidateToTest, evalRes);
                    archive.offer(obj, candidateToTest, evalRes, score, gen);
                }

                progress.updateProgress(archive.getCoveredObjectiveIds().size(), archive.getCoverageRatio());

                if (archive.getCoverageRatio() >= activeConfig.getTargetObjectiveCoverage()) {
                    break;
                }
            }
        }

        // 5. Determine Termination Reason
        TerminationReason terminationReason;
        if (progress.isCancelled()) {
            terminationReason = TerminationReason.CANCELLED;
            progress.setStatus(SearchStatus.CANCELLED);
        } else if (archive.getCoverageRatio() >= activeConfig.getTargetObjectiveCoverage()) {
            terminationReason = TerminationReason.ALL_OBJECTIVES_COVERED;
            progress.setStatus(SearchStatus.COMPLETED);
        } else if (progress.getEvaluationsCompleted() >= activeConfig.getEvaluationBudget()) {
            terminationReason = TerminationReason.EVALUATION_BUDGET_EXHAUSTED;
            progress.setStatus(SearchStatus.COMPLETED);
        } else {
            terminationReason = TerminationReason.MAX_GENERATIONS_REACHED;
            progress.setStatus(SearchStatus.COMPLETED);
        }

        long duration = System.currentTimeMillis() - startTime;
        log.info("Evolutionary search terminated: reason={}, generations={}, evaluations={}, coverage={}/{} ({:.1f}%)",
                terminationReason, progress.getCurrentGeneration(), progress.getEvaluationsCompleted(),
                archive.getCoveredObjectiveIds().size(), objectives.size(), archive.getCoverageRatio() * 100.0);

        return new SearchResult(
                progress.getCurrentGeneration(),
                progress.getEvaluationsCompleted(),
                objectives.size(),
                archive.getCoveredObjectiveIds().size(),
                archive.getCoverageRatio(),
                archive.getArchiveSizes(),
                archive.getAllBestCandidates(),
                terminationReason,
                duration,
                activeConfig.getSeed()
        );
    }

    /**
     * Extracts independent testing objectives from an API specification.
     */
    public List<SearchObjective> extractObjectives(ParsedApiSpecification spec) {
        if (spec == null || spec.getEndpoints().isEmpty()) {
            return List.of();
        }

        List<SearchObjective> list = new ArrayList<>();

        for (ApiEndpoint ep : spec.getEndpoints()) {
            String epId = ep.getIdentifier();

            // 1. Endpoint reached
            list.add(SearchObjective.forEndpoint(epId));

            // 2. Status codes
            list.add(SearchObjective.forStatusCode(epId, 200));
            list.add(SearchObjective.forStatusCode(epId, 400));
            list.add(SearchObjective.forStatusCode(epId, 422));

            // 3. Validation error on required parameters
            for (ApiParameter p : ep.getRequiredParameters()) {
                list.add(SearchObjective.forValidation(epId, p.getName()));
                if (p.getSchema() != null && (p.getSchema().getMinimum() != null || p.getSchema().getMinLength() != null)) {
                    list.add(SearchObjective.forBoundary(epId, p.getName(), "boundary"));
                }
            }

            // 4. Request body schema constraints
            if (ep.hasRequestBody()) {
                ApiSchema bodySchema = ep.getRequestBody().getJsonSchema();
                if (bodySchema != null) {
                    for (String reqProp : bodySchema.getRequiredProperties()) {
                        list.add(SearchObjective.forValidation(epId, reqProp));
                    }
                    for (Map.Entry<String, ApiSchema> prop : bodySchema.getProperties().entrySet()) {
                        ApiSchema ps = prop.getValue();
                        if (ps.getMinimum() != null || ps.getMaximum() != null || ps.getMinLength() != null || ps.getMaxLength() != null) {
                            list.add(SearchObjective.forBoundary(epId, prop.getKey(), "boundary"));
                        }
                    }
                }
            }

            // 5. Server error discovery
            list.add(SearchObjective.forServerError(epId));
        }

        return Collections.unmodifiableList(list);
    }

    private EvaluationResult safeEvaluate(CandidateEvaluator evaluator, ApiTestCase candidate) {
        try {
            return evaluator.evaluate(candidate);
        } catch (Exception e) {
            log.warn("CandidateEvaluator threw exception: {}", e.getMessage());
            return EvaluationResult.failure(candidate.endpointIdentifier(), e.getMessage());
        }
    }

    public FitnessEvaluator getFitnessEvaluator() {
        return fitnessEvaluator;
    }
}

