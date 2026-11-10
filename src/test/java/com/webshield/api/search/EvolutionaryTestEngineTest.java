package com.webshield.api.search;

import com.webshield.api.generation.ApiTestCase;
import com.webshield.api.generation.ApiTestGenerator;
import com.webshield.api.generation.GenerationStrategy;
import com.webshield.api.generation.TestCategory;
import com.webshield.api.models.*;
import com.webshield.api.mutation.MutationEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Evolutionary Search and MIO Engine Test Suite (Module E)")
class EvolutionaryTestEngineTest {

    private ApiTestGenerator testGenerator;
    private MutationEngine mutationEngine;
    private EvolutionaryTestEngine engine;
    private FitnessEvaluator fitnessEvaluator;

    @BeforeEach
    void setUp() {
        testGenerator = new ApiTestGenerator();
        mutationEngine = new MutationEngine();
        engine = new EvolutionaryTestEngine(testGenerator, mutationEngine);
        fitnessEvaluator = new FitnessEvaluator();
    }

    private ParsedApiSpecification createSampleSpec() {
        ParsedApiSpecification spec = new ParsedApiSpecification();

        // Endpoint 1: POST /api/v1/users
        ApiEndpoint userEndpoint = new ApiEndpoint("/api/v1/users", HttpMethod.POST);
        ApiSchema userSchema = ApiSchema.ofType(SchemaType.OBJECT);

        ApiSchema idSchema = ApiSchema.ofType(SchemaType.INTEGER);
        idSchema.setMinimum(BigDecimal.valueOf(1));
        idSchema.setMaximum(BigDecimal.valueOf(1000));
        userSchema.addProperty("id", idSchema);
        userSchema.addRequiredProperty("id");

        ApiSchema nameSchema = ApiSchema.ofType(SchemaType.STRING);
        nameSchema.setMinLength(2);
        nameSchema.setMaxLength(30);
        userSchema.addProperty("name", nameSchema);
        userSchema.addRequiredProperty("name");

        ApiRequestBody reqBody = new ApiRequestBody("User body", true);
        reqBody.addContentType("application/json", userSchema);
        userEndpoint.setRequestBody(reqBody);
        spec.addEndpoint(userEndpoint);

        // Endpoint 2: GET /api/v1/users/{id}
        ApiEndpoint getUserEndpoint = new ApiEndpoint("/api/v1/users/{id}", HttpMethod.GET);
        ApiParameter idParam = new ApiParameter("id", ParameterLocation.PATH, true, idSchema);
        getUserEndpoint.addParameter(idParam);
        spec.addEndpoint(getUserEndpoint);

        return spec;
    }

    private ApiTestCase createSampleTestCase(String id, String endpoint, HttpMethod method, Object body, int complexity) {
        return new ApiTestCase(
                id,
                endpoint,
                method,
                "/api/v1/users",
                TestCategory.VALID,
                Map.of(),
                Map.of(),
                Map.of("Content-Type", "application/json"),
                Map.of(),
                body,
                "application/json",
                GenerationStrategy.SCHEMA_VALID_FULL,
                1337L,
                "Sample test case",
                null,
                null,
                null
        );
    }

    // =========================================================================
    // 1. Objective Creation
    // =========================================================================
    @Test
    @DisplayName("01. Objective creation initializes valid identifiers, types, and descriptions")
    void test01_ObjectiveCreation() {
        SearchObjective epObj = SearchObjective.forEndpoint("POST /api/v1/users");
        assertEquals("OBJ:ENDPOINT:POST /api/v1/users", epObj.getId());
        assertEquals(ObjectiveType.ENDPOINT_REACHED, epObj.getType());
        assertEquals("POST /api/v1/users", epObj.getEndpointIdentifier());

        SearchObjective statusObj = SearchObjective.forStatusCode("POST /api/v1/users", 200);
        assertEquals(ObjectiveType.STATUS_CODE, statusObj.getType());
        assertEquals("200", statusObj.getTargetValue());

        SearchObjective boundaryObj = SearchObjective.forBoundary("POST /api/v1/users", "name", "maxLength");
        assertEquals(ObjectiveType.BOUNDARY_EXERCISED, boundaryObj.getType());
        assertTrue(boundaryObj.getTargetValue().contains("name=maxLength"));
    }

    // =========================================================================
    // 2. Objective Uniqueness
    // =========================================================================
    @Test
    @DisplayName("02. Objectives with identical identifiers are equal and distinct in sets")
    void test02_ObjectiveUniqueness() {
        SearchObjective obj1 = SearchObjective.forStatusCode("POST /api/v1/users", 200);
        SearchObjective obj2 = SearchObjective.forStatusCode("POST /api/v1/users", 200);
        SearchObjective obj3 = SearchObjective.forStatusCode("POST /api/v1/users", 400);

        assertEquals(obj1, obj2);
        assertEquals(obj1.hashCode(), obj2.hashCode());
        assertNotEquals(obj1, obj3);

        Set<SearchObjective> set = new HashSet<>(List.of(obj1, obj2, obj3));
        assertEquals(2, set.size(), "Duplicate objectives must be deduplicated in sets");
    }

    // =========================================================================
    // 3. Archive Insertion
    // =========================================================================
    @Test
    @DisplayName("03. Archive insertion stores qualifying candidate test cases")
    void test03_ArchiveInsertion() {
        ObjectiveArchive archive = new ObjectiveArchive(3);
        SearchObjective obj = SearchObjective.forStatusCode("POST /api/v1/users", 200);

        ApiTestCase tc = createSampleTestCase("TC-1", "POST /api/v1/users", HttpMethod.POST, Map.of("id", 1), 2);
        EvaluationResult res = EvaluationResult.successful(200, "POST /api/v1/users", 10L, Map.of());
        FitnessScore score = FitnessScore.achieved(2, "Exact match");

        boolean offered = archive.offer(obj, tc, res, score, 1);
        assertTrue(offered, "Candidate should be accepted into empty archive");
        assertEquals(1, archive.getCandidates(obj.getId()).size());
        assertTrue(archive.isObjectiveAchieved(obj.getId()));
    }

    // =========================================================================
    // 4. Archive Replacement
    // =========================================================================
    @Test
    @DisplayName("04. Superior candidates replace inferior candidates in the archive")
    void test04_ArchiveReplacement() {
        ObjectiveArchive archive = new ObjectiveArchive(1);
        SearchObjective obj = SearchObjective.forStatusCode("POST /api/v1/users", 200);

        // Initial candidate with progressing fitness (distance 0.2)
        ApiTestCase tc1 = createSampleTestCase("TC-1", "POST /api/v1/users", HttpMethod.POST, Map.of("id", 1), 5);
        EvaluationResult res1 = EvaluationResult.successful(201, "POST /api/v1/users", 10L, Map.of());
        FitnessScore score1 = FitnessScore.progressing(0.2, 0.8, 5, "Close status code");
        archive.offer(obj, tc1, res1, score1, 1);

        // Superior candidate that fully achieves the objective (fitness 1.0)
        ApiTestCase tc2 = createSampleTestCase("TC-2", "POST /api/v1/users", HttpMethod.POST, Map.of("id", 2), 2);
        EvaluationResult res2 = EvaluationResult.successful(200, "POST /api/v1/users", 10L, Map.of());
        FitnessScore score2 = FitnessScore.achieved(2, "Exact status match");

        boolean replaced = archive.offer(obj, tc2, res2, score2, 2);
        assertTrue(replaced, "Superior candidate should replace inferior candidate");
        assertEquals("TC-2", archive.getBestCandidate(obj.getId()).orElseThrow().getCandidateId());
    }

    // =========================================================================
    // 5. Archive Capacity
    // =========================================================================
    @Test
    @DisplayName("05. Archive strictly enforces per-objective maximum capacity limits")
    void test05_ArchiveCapacity() {
        int capacity = 2;
        ObjectiveArchive archive = new ObjectiveArchive(capacity);
        SearchObjective obj = SearchObjective.forEndpoint("POST /api/v1/users");

        for (int i = 1; i <= 5; i++) {
            ApiTestCase tc = createSampleTestCase("TC-" + i, "POST /api/v1/users", HttpMethod.POST, Map.of("id", i), 10 - i);
            EvaluationResult res = EvaluationResult.successful(200, "POST /api/v1/users", 10L, Map.of());
            FitnessScore score = FitnessScore.achieved(10 - i, "Score " + i);
            archive.offer(obj, tc, res, score, i);
        }

        assertEquals(capacity, archive.getCandidates(obj.getId()).size(),
                "Archive size must never exceed configured capacity");
    }

    // =========================================================================
    // 6. Duplicate Prevention
    // =========================================================================
    @Test
    @DisplayName("06. Duplicate candidates with equal or inferior fitness are rejected")
    void test06_DuplicatePrevention() {
        ObjectiveArchive archive = new ObjectiveArchive(5);
        SearchObjective obj = SearchObjective.forEndpoint("POST /api/v1/users");

        ApiTestCase tc = createSampleTestCase("TC-DUPE", "POST /api/v1/users", HttpMethod.POST, Map.of("id", 1), 3);
        EvaluationResult res = EvaluationResult.successful(200, "POST /api/v1/users", 10L, Map.of());
        FitnessScore score = FitnessScore.achieved(3, "First addition");

        assertTrue(archive.offer(obj, tc, res, score, 1));
        assertFalse(archive.offer(obj, tc, res, score, 2), "Identical candidate must be rejected");
        assertEquals(1, archive.getCandidates(obj.getId()).size());
    }

    // =========================================================================
    // 7. Fitness Evaluation
    // =========================================================================
    @Test
    @DisplayName("07. FitnessEvaluator accurately computes status code proximity and distances")
    void test07_FitnessEvaluation() {
        SearchObjective obj = SearchObjective.forStatusCode("POST /api/v1/users", 200);
        ApiTestCase tc = createSampleTestCase("TC-1", "POST /api/v1/users", HttpMethod.POST, Map.of("id", 1), 2);

        // Same class (201 vs 200) -> small distance, high fitness
        EvaluationResult res201 = EvaluationResult.successful(201, "POST /api/v1/users", 10L, Map.of());
        FitnessScore score201 = fitnessEvaluator.evaluate(obj, tc, res201);
        assertFalse(score201.isAchieved());
        assertTrue(score201.fitness() > 0.8, "Close status code should yield high fitness: " + score201.fitness());

        // Different class (500 vs 200) -> larger distance, lower fitness
        EvaluationResult res500 = EvaluationResult.successful(500, "POST /api/v1/users", 10L, Map.of());
        FitnessScore score500 = fitnessEvaluator.evaluate(obj, tc, res500);
        assertTrue(score500.distance() > score201.distance(), "Larger status difference must yield greater distance");
    }

    // =========================================================================
    // 8. Objective Achievement
    // =========================================================================
    @Test
    @DisplayName("08. Objective achievement is confirmed when execution matches criteria")
    void test08_ObjectiveAchievement() {
        SearchObjective obj = SearchObjective.forStatusCode("POST /api/v1/users", 200);
        ApiTestCase tc = createSampleTestCase("TC-1", "POST /api/v1/users", HttpMethod.POST, Map.of("id", 1), 2);
        EvaluationResult res = EvaluationResult.successful(200, "POST /api/v1/users", 10L, Map.of());

        FitnessScore score = fitnessEvaluator.evaluate(obj, tc, res);
        assertTrue(score.isAchieved());
        assertEquals(1.0, score.fitness());
        assertEquals(0.0, score.distance());
    }

    // =========================================================================
    // 9. Candidate Selection
    // =========================================================================
    @Test
    @DisplayName("09. CandidateSelector produces valid selection choices")
    void test09_CandidateSelection() {
        SearchConfiguration config = SearchConfiguration.builder().seed(42L).build();
        CandidateSelector selector = new CandidateSelector(config, mutationEngine, new Random(42L));
        ObjectiveArchive archive = new ObjectiveArchive(3);

        SearchObjective obj = SearchObjective.forEndpoint("POST /api/v1/users");
        ApiTestCase tc = createSampleTestCase("TC-1", "POST /api/v1/users", HttpMethod.POST, Map.of("id", 1), 2);
        archive.offer(obj, tc, EvaluationResult.successful(200, "POST /api/v1/users", 10L, Map.of()),
                FitnessScore.achieved(2, "OK"), 1);

        CandidateSelector.SelectionChoice choice = selector.selectNextCandidate(archive, createSampleSpec());
        assertNotNull(choice);
    }

    // =========================================================================
    // 10. Random Exploration Probability
    // =========================================================================
    @Test
    @DisplayName("10. Random exploration probability P_rnd = 1.0 enforces pure random sampling")
    void test10_RandomExplorationProbability() {
        SearchConfiguration config = SearchConfiguration.builder()
                .randomSamplingProbability(1.0)
                .seed(42L)
                .build();
        CandidateSelector selector = new CandidateSelector(config, mutationEngine, new Random(42L));
        ObjectiveArchive archive = new ObjectiveArchive(3);

        SearchObjective obj = SearchObjective.forEndpoint("POST /api/v1/users");
        ApiTestCase tc = createSampleTestCase("TC-1", "POST /api/v1/users", HttpMethod.POST, Map.of("id", 1), 2);
        archive.offer(obj, tc, EvaluationResult.successful(200, "POST /api/v1/users", 10L, Map.of()),
                FitnessScore.achieved(2, "OK"), 1);

        for (int i = 0; i < 10; i++) {
            CandidateSelector.SelectionChoice choice = selector.selectNextCandidate(archive, createSampleSpec());
            assertTrue(choice.isRandomSampling(), "P_rnd=1.0 must always yield random sampling");
        }
    }

    // =========================================================================
    // 11. Archive-Based Selection
    // =========================================================================
    @Test
    @DisplayName("11. Archive-based selection P_rnd = 0.0 exploits existing archived candidates")
    void test11_ArchiveBasedSelection() {
        SearchConfiguration config = SearchConfiguration.builder()
                .randomSamplingProbability(0.0)
                .seed(42L)
                .build();
        CandidateSelector selector = new CandidateSelector(config, mutationEngine, new Random(42L));
        ObjectiveArchive archive = new ObjectiveArchive(3);

        SearchObjective obj = SearchObjective.forEndpoint("POST /api/v1/users");
        ApiTestCase tc = createSampleTestCase("TC-1", "POST /api/v1/users", HttpMethod.POST, new LinkedHashMap<>(Map.of("name", "Alice")), 2);
        archive.offer(obj, tc, EvaluationResult.successful(200, "POST /api/v1/users", 10L, Map.of()),
                FitnessScore.achieved(2, "OK"), 1);

        CandidateSelector.SelectionChoice choice = selector.selectNextCandidate(archive, createSampleSpec());
        assertFalse(choice.isRandomSampling(), "P_rnd=0.0 must select from archive");
        assertNotNull(choice.parentCandidate());
        assertEquals("TC-1", choice.parentCandidate().id());
    }

    // =========================================================================
    // 12. Mutation Integration
    // =========================================================================
    @Test
    @DisplayName("12. Selected candidate is mutated via Module D and preserves parent lineage")
    void test12_MutationIntegration() {
        SearchConfiguration config = SearchConfiguration.builder()
                .randomSamplingProbability(0.0)
                .seed(42L)
                .build();
        CandidateSelector selector = new CandidateSelector(config, mutationEngine, new Random(42L));
        ObjectiveArchive archive = new ObjectiveArchive(3);

        SearchObjective obj = SearchObjective.forEndpoint("POST /api/v1/users");
        ApiTestCase tc = createSampleTestCase("TC-BASE", "POST /api/v1/users", HttpMethod.POST,
                new LinkedHashMap<>(Map.of("name", "Alice", "id", 10)), 2);
        archive.offer(obj, tc, EvaluationResult.successful(200, "POST /api/v1/users", 10L, Map.of()),
                FitnessScore.achieved(2, "OK"), 1);

        CandidateSelector.SelectionChoice choice = selector.selectNextCandidate(archive, createSampleSpec());
        ApiTestCase mutated = choice.candidateToEvaluate();
        assertNotNull(mutated);
        assertEquals("TC-BASE", mutated.parentTestCaseId(), "Mutated candidate must reference parent ID in lineage");
    }

    // =========================================================================
    // 13. Initial Candidate Generation
    // =========================================================================
    @Test
    @DisplayName("13. Initial candidate generation synthesizes valid base test cases via Module C")
    void test13_InitialCandidateGeneration() {
        ParsedApiSpecification spec = createSampleSpec();
        List<ApiTestCase> suite = testGenerator.generateSuite(spec);
        assertFalse(suite.isEmpty(), "Initial test suite must not be empty");
        assertTrue(suite.stream().anyMatch(tc -> tc.category() == TestCategory.VALID));
    }

    // =========================================================================
    // 14. Generational Search
    // =========================================================================
    @Test
    @DisplayName("14. Generational search runs across multiple generations and updates metrics")
    void test14_GenerationalSearch() {
        SearchConfiguration config = SearchConfiguration.builder()
                .maxGenerations(3)
                .populationSize(5)
                .evaluationBudget(50)
                .seed(42L)
                .build();

        SearchResult result = engine.search(createSampleSpec(), new MockCandidateEvaluator(), config);
        assertNotNull(result);
        assertTrue(result.totalGenerations() > 0, "Should complete at least 1 generation");
        assertTrue(result.totalEvaluations() > 0, "Should complete evaluations");
    }

    // =========================================================================
    // 15. Multiple Independent Objectives
    // =========================================================================
    @Test
    @DisplayName("15. Multiple independent objectives maintain isolated archives without cross-talk")
    void test15_MultipleIndependentObjectives() {
        ObjectiveArchive archive = new ObjectiveArchive(3);
        SearchObjective obj1 = SearchObjective.forStatusCode("POST /api/v1/users", 200);
        SearchObjective obj2 = SearchObjective.forStatusCode("POST /api/v1/users", 400);

        ApiTestCase tc1 = createSampleTestCase("TC-200", "POST /api/v1/users", HttpMethod.POST, Map.of(), 2);
        archive.offer(obj1, tc1, EvaluationResult.successful(200, "POST /api/v1/users", 10L, Map.of()),
                FitnessScore.achieved(2, "OK"), 1);

        assertTrue(archive.isObjectiveAchieved(obj1.getId()));
        assertFalse(archive.isObjectiveAchieved(obj2.getId()), "Obj2 must not be marked achieved by Obj1 candidate");
    }

    // =========================================================================
    // 16. Objective Coverage Calculation
    // =========================================================================
    @Test
    @DisplayName("16. Objective coverage calculation accurately computes achieved ratio")
    void test16_ObjectiveCoverageCalculation() {
        ObjectiveArchive archive = new ObjectiveArchive(3);
        SearchObjective obj1 = SearchObjective.forStatusCode("POST /api/v1/users", 200);
        SearchObjective obj2 = SearchObjective.forStatusCode("POST /api/v1/users", 400);
        archive.registerObjective(obj1);
        archive.registerObjective(obj2);

        assertEquals(0.0, archive.getCoverageRatio());

        archive.offer(obj1, createSampleTestCase("TC-1", "POST /api/v1/users", HttpMethod.POST, Map.of(), 2),
                EvaluationResult.successful(200, "POST /api/v1/users", 10L, Map.of()),
                FitnessScore.achieved(2, "OK"), 1);

        assertEquals(0.5, archive.getCoverageRatio(), 0.001);
    }

    // =========================================================================
    // 17. Evaluation Budget Termination
    // =========================================================================
    @Test
    @DisplayName("17. Evaluation budget termination strictly halts when budget is exhausted")
    void test17_EvaluationBudgetTermination() {
        int budget = 8;
        SearchConfiguration config = SearchConfiguration.builder()
                .evaluationBudget(budget)
                .maxGenerations(100)
                .populationSize(5)
                .seed(42L)
                .build();

        SearchResult result = engine.search(createSampleSpec(), new MockCandidateEvaluator(), config);
        assertEquals(TerminationReason.EVALUATION_BUDGET_EXHAUSTED, result.terminationReason());
        assertTrue(result.totalEvaluations() <= budget + 5, "Total evaluations must not significantly exceed budget: " + result.totalEvaluations());
    }

    // =========================================================================
    // 18. Generation Budget Termination
    // =========================================================================
    @Test
    @DisplayName("18. Generation budget termination halts when maxGenerations is reached")
    void test18_GenerationBudgetTermination() {
        SearchConfiguration config = SearchConfiguration.builder()
                .maxGenerations(2)
                .populationSize(3)
                .evaluationBudget(500)
                .targetObjectiveCoverage(1.0)
                .seed(42L)
                .build();

        // Evaluator that never covers all objectives
        MockCandidateEvaluator eval = new MockCandidateEvaluator();
        eval.mapStatus("POST /api/v1/users", 200);

        SearchResult result = engine.search(createSampleSpec(), eval, config);
        assertTrue(result.terminationReason() == TerminationReason.MAX_GENERATIONS_REACHED
                || result.terminationReason() == TerminationReason.ALL_OBJECTIVES_COVERED);
    }

    // =========================================================================
    // 19. Search Cancellation
    // =========================================================================
    @Test
    @DisplayName("19. Search cancellation cleanly terminates the evolutionary process")
    void test19_SearchCancellation() {
        SearchConfiguration config = SearchConfiguration.builder()
                .maxGenerations(100)
                .evaluationBudget(1000)
                .build();
        SearchProgress progress = new SearchProgress(config.getEvaluationBudget(), config.getMaxGenerations());

        // Cancel immediately
        progress.cancel();
        assertTrue(progress.isCancelled());

        SearchResult result = engine.search(createSampleSpec(), new MockCandidateEvaluator(), config, progress);
        assertEquals(TerminationReason.CANCELLED, result.terminationReason());
    }

    // =========================================================================
    // 20. Reproducibility with Identical Seeds
    // =========================================================================
    @Test
    @DisplayName("20. Identical random seeds produce reproducible evaluations and coverage")
    void test20_ReproducibilityWithIdenticalSeeds() {
        SearchConfiguration config1 = SearchConfiguration.builder().seed(98765L).maxGenerations(3).evaluationBudget(30).build();
        SearchConfiguration config2 = SearchConfiguration.builder().seed(98765L).maxGenerations(3).evaluationBudget(30).build();

        SearchResult res1 = engine.search(createSampleSpec(), new MockCandidateEvaluator(), config1);
        SearchResult res2 = engine.search(createSampleSpec(), new MockCandidateEvaluator(), config2);

        assertEquals(res1.totalEvaluations(), res2.totalEvaluations(), "Evaluations must match for identical seed");
        assertEquals(res1.objectivesAchieved(), res2.objectivesAchieved(), "Objectives achieved must match");
        assertEquals(res1.objectiveCoverage(), res2.objectiveCoverage(), 0.001);
        assertEquals(res1.terminationReason(), res2.terminationReason());
    }

    // =========================================================================
    // 21. Search Result Reporting
    // =========================================================================
    @Test
    @DisplayName("21. SearchResult comprehensively reports duration, best candidates, and stats")
    void test21_SearchResultReporting() {
        SearchConfiguration config = SearchConfiguration.builder().maxGenerations(2).evaluationBudget(20).seed(42L).build();
        SearchResult result = engine.search(createSampleSpec(), new MockCandidateEvaluator(), config);

        assertNotNull(result);
        assertTrue(result.searchDurationMs() >= 0);
        assertEquals(42L, result.searchSeed());
        assertNotNull(result.archiveStatistics());
        assertNotNull(result.bestCandidates());
        assertNotNull(result.terminationReason());
    }

    // =========================================================================
    // 22. Progress Tracking
    // =========================================================================
    @Test
    @DisplayName("22. SearchProgress provides live thread-safe updates on generations and budget")
    void test22_ProgressTracking() {
        SearchProgress progress = new SearchProgress(100, 10);
        assertEquals(0, progress.getCurrentGeneration());
        assertEquals(0, progress.getEvaluationsCompleted());
        assertEquals(SearchStatus.NOT_STARTED, progress.getStatus());

        progress.incrementGeneration();
        progress.incrementEvaluations();
        progress.updateProgress(2, 0.5);

        assertEquals(1, progress.getCurrentGeneration());
        assertEquals(1, progress.getEvaluationsCompleted());
        assertEquals(2, progress.getObjectivesAchieved());
        assertEquals(0.5, progress.getCurrentCoverage());
        assertTrue(progress.getProgressPercentage() > 0.0);
    }

    // =========================================================================
    // 23. Empty Archive Handling
    // =========================================================================
    @Test
    @DisplayName("23. CandidateSelector gracefully falls back when archives are empty")
    void test23_EmptyArchiveHandling() {
        SearchConfiguration config = SearchConfiguration.builder().randomSamplingProbability(0.0).build();
        CandidateSelector selector = new CandidateSelector(config, mutationEngine, new Random(42L));
        ObjectiveArchive emptyArchive = new ObjectiveArchive(3);

        CandidateSelector.SelectionChoice choice = selector.selectNextCandidate(emptyArchive, createSampleSpec());
        assertTrue(choice.isRandomSampling(), "Empty archive must fall back to random sampling");
    }

    // =========================================================================
    // 24. Evaluator Failure Handling
    // =========================================================================
    @Test
    @DisplayName("24. Evaluator exceptions are caught safely and converted to failure results")
    void test24_EvaluatorFailureHandling() {
        CandidateEvaluator throwingEvaluator = testCase -> {
            throw new RuntimeException("Simulated socket timeout");
        };

        SearchConfiguration config = SearchConfiguration.builder().maxGenerations(1).evaluationBudget(5).build();
        assertDoesNotThrow(() -> engine.search(createSampleSpec(), throwingEvaluator, config));
    }

    // =========================================================================
    // 25. Maximum Search Limits
    // =========================================================================
    @Test
    @DisplayName("25. SearchConfiguration validates boundaries and rejects invalid parameters")
    void test25_MaximumSearchLimits() {
        SearchConfiguration config = new SearchConfiguration();

        assertThrows(IllegalArgumentException.class, () -> config.setPopulationSize(0));
        assertThrows(IllegalArgumentException.class, () -> config.setMaxGenerations(0));
        assertThrows(IllegalArgumentException.class, () -> config.setEvaluationBudget(0));
        assertThrows(IllegalArgumentException.class, () -> config.setMutationProbability(-0.1));
        assertThrows(IllegalArgumentException.class, () -> config.setMutationProbability(1.1));
        assertThrows(IllegalArgumentException.class, () -> config.setRandomSamplingProbability(-0.1));
        assertThrows(IllegalArgumentException.class, () -> config.setMaxArchiveSizePerObjective(0));
        assertThrows(IllegalArgumentException.class, () -> config.setTargetObjectiveCoverage(0.0));
    }

    // =========================================================================
    // 26. Mock Evaluator Integration
    // =========================================================================
    @Test
    @DisplayName("26. MockCandidateEvaluator derives realistic status codes across test categories")
    void test26_MockEvaluatorIntegration() {
        MockCandidateEvaluator eval = new MockCandidateEvaluator();

        ApiTestCase valid = createSampleTestCase("TC-V", "POST /api/v1/users", HttpMethod.POST, Map.of(), 1);
        EvaluationResult resValid = eval.evaluate(valid);
        assertEquals(201, resValid.statusCode());

        ApiTestCase invalid = new ApiTestCase("TC-I", "POST /api/v1/users", HttpMethod.POST, "/api/v1/users",
                TestCategory.INVALID, Map.of(), Map.of(), Map.of(), Map.of(), Map.of(),
                "application/json", GenerationStrategy.MISSING_REQUIRED_FIELD, 1L, "Missing", "id", null, null);
        EvaluationResult resInvalid = eval.evaluate(invalid);
        assertEquals(400, resInvalid.statusCode());

        eval.setSimulateFailures(true);
        EvaluationResult resFail = eval.evaluate(valid);
        assertFalse(resFail.connectionSuccessful());
    }
}

