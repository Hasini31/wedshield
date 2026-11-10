package com.webshield.api.mutation;

import com.webshield.api.generation.ApiTestCase;
import com.webshield.api.generation.GenerationStrategy;
import com.webshield.api.generation.TestCategory;
import com.webshield.api.models.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("API Input Mutation Engine Test Suite (Module D)")
class MutationEngineTest {

    private MutationEngine engine;
    private MutationConfig defaultConfig;

    @BeforeEach
    void setUp() {
        defaultConfig = MutationConfig.builder()
                .seed(1337L)
                .mutationProbability(1.0) // 100% deterministic inclusion for testing
                .maxMutationsPerTestCase(20)
                .maxMutationDepth(3)
                .maxTotalMutations(100)
                .build();
        engine = new MutationEngine(defaultConfig);
    }

    private ApiTestCase createBaseTestCase(Object body, Map<String, Object> query, Map<String, Object> path) {
        return new ApiTestCase(
                "TC-BASE-001",
                "POST /api/v1/users",
                HttpMethod.POST,
                "/api/v1/users",
                TestCategory.VALID,
                path != null ? path : Map.of(),
                query != null ? query : Map.of(),
                Map.of("Content-Type", "application/json"),
                Map.of(),
                body,
                "application/json",
                GenerationStrategy.SCHEMA_VALID_FULL,
                1337L,
                "Base valid test case",
                null,
                null,
                null
        );
    }

    private ApiEndpoint createUserEndpoint() {
        ApiEndpoint endpoint = new ApiEndpoint("/api/v1/users", HttpMethod.POST);
        ApiSchema userSchema = ApiSchema.ofType(SchemaType.OBJECT);

        ApiSchema idSchema = ApiSchema.ofType(SchemaType.INTEGER);
        idSchema.setMinimum(BigDecimal.valueOf(1));
        idSchema.setMaximum(BigDecimal.valueOf(1000));
        userSchema.addProperty("id", idSchema);
        userSchema.addRequiredProperty("id");

        ApiSchema nameSchema = ApiSchema.ofType(SchemaType.STRING);
        nameSchema.setMinLength(2);
        nameSchema.setMaxLength(50);
        userSchema.addProperty("name", nameSchema);
        userSchema.addRequiredProperty("name");

        ApiSchema roleSchema = ApiSchema.ofType(SchemaType.STRING);
        roleSchema.setEnumValues(List.of("ADMIN", "USER", "GUEST"));
        userSchema.addProperty("role", roleSchema);

        ApiSchema activeSchema = ApiSchema.ofType(SchemaType.BOOLEAN);
        userSchema.addProperty("active", activeSchema);

        ApiSchema scoreSchema = ApiSchema.ofType(SchemaType.NUMBER);
        scoreSchema.setFormat("float");
        userSchema.addProperty("score", scoreSchema);

        ApiRequestBody requestBody = new ApiRequestBody("User body", true);
        requestBody.addContentType("application/json", userSchema);
        endpoint.setRequestBody(requestBody);

        ApiParameter pageParam = new ApiParameter("page", ParameterLocation.QUERY, false, ApiSchema.ofType(SchemaType.INTEGER));
        endpoint.addParameter(pageParam);

        return endpoint;
    }

    // =========================================================================
    // 1. String Insertion
    // =========================================================================
    @Test
    @DisplayName("01. String insertion increases length by 1 and preserves existing characters")
    void test01_StringInsertion() {
        String original = "adminUser";
        String mutated = StringMutation.insertCharacters(original, new Random(42L));
        assertEquals(original.length() + 1, mutated.length(), "String length must increase by exactly 1");

        // Verify with engine
        ApiTestCase base = createBaseTestCase(new LinkedHashMap<>(Map.of("name", original)), null, null);
        MutationResult res = engine.mutateField(base, createUserEndpoint(), "body.name", MutationOperatorType.STRING_INSERTION, 42L);
        assertNotNull(res);
        assertEquals(original.length() + 1, ((String) res.context().mutatedValue()).length());
    }

    // =========================================================================
    // 2. String Deletion
    // =========================================================================
    @Test
    @DisplayName("02. String deletion decreases length by 1 from non-empty string")
    void test02_StringDeletion() {
        String original = "adminUser";
        String mutated = StringMutation.deleteCharacters(original, new Random(42L));
        assertEquals(original.length() - 1, mutated.length(), "String length must decrease by exactly 1");

        // Edge case: single character string
        assertEquals("", StringMutation.deleteCharacters("A", new Random(42L)));
        assertEquals("", StringMutation.deleteCharacters("", new Random(42L)));
    }

    // =========================================================================
    // 3. String Replacement
    // =========================================================================
    @Test
    @DisplayName("03. String replacement alters a character while maintaining total length")
    void test03_StringReplacement() {
        String original = "adminUser";
        String mutated = StringMutation.replaceCharacters(original, new Random(42L));
        assertEquals(original.length(), mutated.length(), "String length should remain constant");
        assertNotEquals(original, mutated, "Mutated string must differ from original");
    }

    // =========================================================================
    // 4. Special Character Injection
    // =========================================================================
    @Test
    @DisplayName("04. Special character and delimiter injection introduces safe punctuation")
    void test04_SpecialCharacterInjection() {
        String original = "adminUser";
        String withSpecial = StringMutation.injectSpecialCharacters(original, new Random(42L));
        assertTrue(withSpecial.length() > original.length());
        assertTrue(withSpecial.chars().anyMatch(ch -> StringMutation.SPECIAL_CHARACTERS.contains((char) ch)),
                "Mutated string must contain a special character");

        String withDelimiter = StringMutation.injectQuotesAndDelimiters(original, new Random(42L));
        assertTrue(withDelimiter.length() > original.length());
    }

    // =========================================================================
    // 5. Unicode Mutation
    // =========================================================================
    @Test
    @DisplayName("05. Unicode mutation injects multi-byte, non-ASCII, and boundary characters")
    void test05_UnicodeMutation() {
        String original = "adminUser";
        String mutated = StringMutation.injectUnicode(original, new Random(42L));
        assertTrue(mutated.length() > original.length());
        boolean hasNonAscii = mutated.chars().anyMatch(ch -> ch > 127);
        assertTrue(hasNonAscii, "Mutated string must contain multi-byte Unicode or non-ASCII characters");
    }

    // =========================================================================
    // 6. Numeric Increment and Decrement
    // =========================================================================
    @Test
    @DisplayName("06. Numeric increment and decrement alter integers and floats by unit delta")
    void test06_NumericIncrementAndDecrement() {
        assertEquals(101, NumericMutation.increment(100));
        assertEquals(99, NumericMutation.decrement(100));

        assertEquals(101L, NumericMutation.increment(100L));
        assertEquals(99L, NumericMutation.decrement(100L));

        assertEquals(101.5, NumericMutation.increment(100.5));
        assertEquals(99.5, NumericMutation.decrement(100.5));
    }

    // =========================================================================
    // 7. Negative Number Generation
    // =========================================================================
    @Test
    @DisplayName("07. Negative number generation and sign reversal produce negative quantities")
    void test07_NegativeNumberGeneration() {
        Number negInt = NumericMutation.negativeValue(50, false);
        assertTrue(negInt.longValue() < 0, "Value must be negative: " + negInt);

        Number negFloat = NumericMutation.negativeValue(25.5, true);
        assertTrue(negFloat.doubleValue() < 0, "Value must be negative: " + negFloat);

        Number reversed = NumericMutation.signReversal(75);
        assertEquals(-75L, reversed.longValue());

        Number reversedNeg = NumericMutation.signReversal(-75);
        assertEquals(75L, reversedNeg.longValue());
    }

    // =========================================================================
    // 8. Numeric Boundary Mutation
    // =========================================================================
    @Test
    @DisplayName("08. Numeric boundary mutations target schema minimum/maximum and out-of-bounds")
    void test08_NumericBoundaryMutation() {
        ApiSchema schema = ApiSchema.ofType(SchemaType.INTEGER);
        schema.setMinimum(BigDecimal.valueOf(10));
        schema.setMaximum(BigDecimal.valueOf(100));

        Number minVal = NumericMutation.boundaryMinMax(schema, false, new Random(0L));
        assertTrue(minVal.longValue() == 10L || minVal.longValue() == 100L);

        Number outVal = NumericMutation.outsideBounds(schema, false, new Random(0L));
        assertTrue(outVal.longValue() == 9L || outVal.longValue() == 101L);
    }

    // =========================================================================
    // 9. Boolean Mutation
    // =========================================================================
    @Test
    @DisplayName("09. Boolean mutation correctly inverts values and injects null")
    void test09_BooleanMutation() {
        assertEquals(Boolean.FALSE, BooleanMutation.invert(Boolean.TRUE));
        assertEquals(Boolean.TRUE, BooleanMutation.invert(Boolean.FALSE));
        assertNull(BooleanMutation.nullInjection());
    }

    // =========================================================================
    // 10. Enum Mutation
    // =========================================================================
    @Test
    @DisplayName("10. Enum mutation tests valid replacement, invalid injection, casing, and null")
    void test10_EnumMutation() {
        ApiSchema roleSchema = ApiSchema.ofType(SchemaType.STRING);
        roleSchema.setEnumValues(List.of("ADMIN", "USER", "GUEST"));

        String replaced = EnumMutation.replaceValid("ADMIN", roleSchema, new Random(42L));
        assertTrue(List.of("USER", "GUEST").contains(replaced), "Replaced value should be an alternative valid enum: " + replaced);

        String invalid = EnumMutation.injectInvalid("ADMIN", new Random(42L));
        assertTrue(invalid.contains("UNKNOWN") || invalid.contains("INVALID"));

        assertEquals("admin", EnumMutation.caseVariation("ADMIN"));
        assertEquals("ACTIVE", EnumMutation.caseVariation("active"));
        assertEquals("", EnumMutation.emptyValue());
        assertNull(EnumMutation.nullValue());
    }

    // =========================================================================
    // 11. Optional Property Removal
    // =========================================================================
    @Test
    @DisplayName("11. Optional property removal preserves required fields while omitting optional ones")
    void test11_OptionalPropertyRemoval() {
        ApiSchema schema = ApiSchema.ofType(SchemaType.OBJECT);
        schema.addProperty("id", ApiSchema.ofType(SchemaType.INTEGER));
        schema.addRequiredProperty("id");
        schema.addProperty("nickname", ApiSchema.ofType(SchemaType.STRING));

        Map<String, Object> input = new LinkedHashMap<>();
        input.put("id", 101);
        input.put("nickname", "FastEddie");

        Map<String, Object> mutated = StructureMutation.removeOptionalProperty(input, schema, new Random(42L));
        assertTrue(mutated.containsKey("id"), "Required property 'id' must be preserved");
        assertFalse(mutated.containsKey("nickname"), "Optional property 'nickname' should be removed");
    }

    // =========================================================================
    // 12. Required Property Removal
    // =========================================================================
    @Test
    @DisplayName("12. Required property removal systematically omits declared mandatory properties")
    void test12_RequiredPropertyRemoval() {
        ApiSchema schema = ApiSchema.ofType(SchemaType.OBJECT);
        schema.addProperty("id", ApiSchema.ofType(SchemaType.INTEGER));
        schema.addRequiredProperty("id");

        Map<String, Object> input = new LinkedHashMap<>();
        input.put("id", 101);
        input.put("nickname", "FastEddie");

        Map<String, Object> mutated = StructureMutation.removeRequiredProperty(input, schema, new Random(42L));
        assertFalse(mutated.containsKey("id"), "Required property 'id' must be removed");
    }

    // =========================================================================
    // 13. Unexpected Property Insertion
    // =========================================================================
    @Test
    @DisplayName("13. Unexpected property insertion adds undeclared keys to JSON object")
    void test13_UnexpectedPropertyInsertion() {
        Map<String, Object> input = new LinkedHashMap<>(Map.of("id", 101));
        Map<String, Object> mutated = StructureMutation.addUnexpectedProperty(input, new Random(42L));

        assertEquals(2, mutated.size());
        assertTrue(mutated.keySet().stream().anyMatch(k -> k.startsWith("__unexpected_property_")));
    }

    // =========================================================================
    // 14. Nested Object Mutation
    // =========================================================================
    @Test
    @DisplayName("14. Nested object mutation duplicates structures and alters nested data types")
    void test14_NestedObjectMutation() {
        Map<String, Object> address = new LinkedHashMap<>(Map.of("city", "Boston", "zip", "02101"));
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("id", 101);
        input.put("address", address);

        Map<String, Object> duplicated = StructureMutation.duplicateNestedStructure(input, new Random(42L));
        assertTrue(duplicated.containsKey("address_duplicated"), "Duplicated nested property should be present");

        Map<String, Object> typeChanged = StructureMutation.changeNestedObjectType(input, new Random(42L));
        assertFalse(typeChanged.get("address") instanceof Map<?, ?>, "Nested object type must be altered to non-Map");
    }

    // =========================================================================
    // 15. Array Mutation
    // =========================================================================
    @Test
    @DisplayName("15. Array mutation handles length shifts, truncation, and unwrapping")
    void test15_ArrayMutation() {
        List<Object> items = new ArrayList<>(List.of("alpha", "beta", "gamma"));

        List<Object> truncated = StructureMutation.changeArrayLength(items, new Random(0L));
        assertNotEquals(items.size(), truncated.size());

        Object unwrapped = StructureMutation.unwrapArray(items);
        assertEquals("alpha", unwrapped);
    }

    // =========================================================================
    // 16. Type Replacement
    // =========================================================================
    @Test
    @DisplayName("16. Type replacement swaps primitives with objects and objects with primitives")
    void test16_TypeReplacement() {
        Map<String, Object> obj = Map.of("key", "val");
        Object primitive = StructureMutation.replaceObjectWithPrimitive(obj);
        assertTrue(primitive instanceof String, "Object must be replaced with primitive string");

        Object replacedObj = StructureMutation.replacePrimitiveWithObject("someString");
        assertTrue(replacedObj instanceof Map<?, ?>, "Primitive must be replaced with object map");
    }

    // =========================================================================
    // 17. Parent Test Case Preservation
    // =========================================================================
    @Test
    @DisplayName("17. Parent test case is strictly preserved and never modified during mutation")
    void test17_ParentTestCasePreservation() {
        Map<String, Object> parentBody = new LinkedHashMap<>();
        parentBody.put("id", 101);
        parentBody.put("name", "Alice");

        Map<String, Object> parentQuery = new LinkedHashMap<>();
        parentQuery.put("page", 1);

        ApiTestCase parent = createBaseTestCase(parentBody, parentQuery, null);

        // Generate full mutation list
        List<MutationResult> results = engine.mutateTestCase(parent, createUserEndpoint());
        assertFalse(results.isEmpty(), "Should produce mutated test cases");

        // Verify parent state is strictly identical
        assertEquals(101, ((Map<?, ?>) parent.requestBody()).get("id"));
        assertEquals("Alice", ((Map<?, ?>) parent.requestBody()).get("name"));
        assertEquals(2, ((Map<?, ?>) parent.requestBody()).size());
        assertEquals(1, parent.queryParameters().get("page"));
        assertNull(parent.parentTestCaseId());
    }

    // =========================================================================
    // 18. Mutation Lineage
    // =========================================================================
    @Test
    @DisplayName("18. Mutation lineage tracks parent ID, operator, generation depth, and description")
    void test18_MutationLineage() {
        ApiTestCase parent = createBaseTestCase(new LinkedHashMap<>(Map.of("name", "Alice")), null, null);
        List<MutationResult> results = engine.mutateTestCase(parent, createUserEndpoint());

        for (MutationResult res : results) {
            assertEquals(parent.id(), res.getParentTestCaseId());
            assertEquals(parent.id(), res.testCase().parentTestCaseId());
            assertEquals(1, res.getGeneration());
            assertNotNull(res.getOperatorType());
            assertNotNull(res.context().description());
            assertTrue(res.getId().startsWith("MUT-TC-BASE-001-GEN1-"));
        }
    }

    // =========================================================================
    // 19. Deterministic Random Seeds
    // =========================================================================
    @Test
    @DisplayName("19. Deterministic random seeds produce identical mutation outputs across engines")
    void test19_DeterministicRandomSeeds() {
        MutationConfig cfg = MutationConfig.builder().seed(9999L).build();
        MutationEngine engine1 = new MutationEngine(cfg);
        MutationEngine engine2 = new MutationEngine(cfg);

        ApiTestCase parent = createBaseTestCase(new LinkedHashMap<>(Map.of("name", "Alice", "id", 10)), null, null);

        List<MutationResult> res1 = engine1.mutateTestCase(parent, createUserEndpoint(), cfg);
        List<MutationResult> res2 = engine2.mutateTestCase(parent, createUserEndpoint(), cfg);

        assertEquals(res1.size(), res2.size());
        for (int i = 0; i < res1.size(); i++) {
            assertEquals(res1.get(i).getOperatorType(), res2.get(i).getOperatorType());
            assertEquals(res1.get(i).getTargetedField(), res2.get(i).getTargetedField());
            assertEquals(res1.get(i).context().mutatedValue(), res2.get(i).context().mutatedValue());
        }
    }

    // =========================================================================
    // 20. Duplicate Prevention
    // =========================================================================
    @Test
    @DisplayName("20. Duplicate prevention ensures all generated test cases have unique signatures")
    void test20_DuplicatePrevention() {
        ApiTestCase parent = createBaseTestCase(new LinkedHashMap<>(Map.of("name", "Alice", "id", 10)), null, null);
        List<MutationResult> results = engine.mutateTestCase(parent, createUserEndpoint());

        Set<String> signatures = new HashSet<>();
        for (MutationResult res : results) {
            String sig = res.getOperatorType() + "|" + res.getTargetedField() + "|"
                    + Objects.hashCode(res.testCase().requestBody());
            assertTrue(signatures.add(sig), "Duplicate mutation detected: " + sig);
        }
    }

    // =========================================================================
    // 21. Mutation Limits
    // =========================================================================
    @Test
    @DisplayName("21. Mutation limits cap mutations per test case and across the suite")
    void test21_MutationLimits() {
        MutationConfig cappedConfig = MutationConfig.builder()
                .maxMutationsPerTestCase(4)
                .maxTotalMutations(6)
                .build();

        ApiTestCase parent = createBaseTestCase(new LinkedHashMap<>(Map.of("name", "Alice", "id", 10, "role", "ADMIN")), null, null);
        List<MutationResult> results = engine.mutateTestCase(parent, createUserEndpoint(), cappedConfig);
        assertTrue(results.size() <= 4, "Should not exceed maxMutationsPerTestCase limit");

        ParsedApiSpecification spec = new ParsedApiSpecification();
        spec.addEndpoint(createUserEndpoint());

        List<MutationResult> suiteResults = engine.mutateSuite(List.of(parent, parent, parent), spec, cappedConfig);
        assertTrue(suiteResults.size() <= 6, "Should not exceed maxTotalMutations limit");
    }

    // =========================================================================
    // 22. Maximum Depth Handling
    // =========================================================================
    @Test
    @DisplayName("22. Maximum depth handling restricts multi-generation recursive mutation")
    void test22_MaximumDepthHandling() {
        MutationConfig depthConfig = MutationConfig.builder()
                .maxMutationDepth(2)
                .build();

        ApiTestCase gen0 = createBaseTestCase(new LinkedHashMap<>(Map.of("name", "Alice")), null, null);

        // Gen 1
        List<MutationResult> gen1List = engine.mutateTestCase(gen0, createUserEndpoint(), depthConfig);
        assertFalse(gen1List.isEmpty());
        ApiTestCase gen1 = gen1List.get(0).testCase();
        assertEquals(1, gen1List.get(0).getGeneration());

        // Gen 2
        List<MutationResult> gen2List = engine.mutateTestCase(gen1, createUserEndpoint(), depthConfig);
        assertFalse(gen2List.isEmpty());
        ApiTestCase gen2 = gen2List.get(0).testCase();
        assertEquals(2, gen2List.get(0).getGeneration());

        // Gen 3 (exceeds max depth 2)
        List<MutationResult> gen3List = engine.mutateTestCase(gen2, createUserEndpoint(), depthConfig);
        assertTrue(gen3List.isEmpty(), "Should reject mutations when max depth is reached");
    }

    // =========================================================================
    // 23. Schema-Aware Operator Selection
    // =========================================================================
    @Test
    @DisplayName("23. Schema-aware operator selection only targets relevant data types")
    void test23_SchemaAwareOperatorSelection() {
        ApiSchema intSchema = ApiSchema.ofType(SchemaType.INTEGER);
        List<MutationOperatorType> numericOps = engine.selectApplicableOperators(10, intSchema, defaultConfig);
        assertTrue(numericOps.stream().allMatch(op -> op.getCategory() == MutationCategory.NUMERIC));

        ApiSchema enumSchema = ApiSchema.ofType(SchemaType.STRING);
        enumSchema.setEnumValues(List.of("A", "B"));
        List<MutationOperatorType> enumOps = engine.selectApplicableOperators("A", enumSchema, defaultConfig);
        assertTrue(enumOps.stream().allMatch(op -> op.getCategory() == MutationCategory.ENUM));

        ApiSchema strSchema = ApiSchema.ofType(SchemaType.STRING);
        List<MutationOperatorType> strOps = engine.selectApplicableOperators("hello", strSchema, defaultConfig);
        assertTrue(strOps.stream().allMatch(op -> op.getCategory() == MutationCategory.STRING));
    }

    // =========================================================================
    // 24. Mutation Category Configuration
    // =========================================================================
    @Test
    @DisplayName("24. Disabling specific mutation categories suppresses those operators completely")
    void test24_MutationCategoryConfiguration() {
        MutationConfig numericOnly = MutationConfig.builder()
                .enabledCategories(Set.of(MutationCategory.NUMERIC))
                .build();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", 101);
        body.put("name", "Alice");
        body.put("active", true);

        ApiTestCase parent = createBaseTestCase(body, null, null);
        List<MutationResult> results = engine.mutateTestCase(parent, createUserEndpoint(), numericOnly);

        assertFalse(results.isEmpty());
        assertTrue(results.stream().allMatch(r -> r.getOperatorType().getCategory() == MutationCategory.NUMERIC),
                "All mutations must belong to the enabled NUMERIC category");
    }
}
