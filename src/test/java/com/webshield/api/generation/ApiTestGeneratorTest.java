package com.webshield.api.generation;

import com.webshield.api.models.*;
import com.webshield.api.parser.OpenApiParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Module C: ApiTestGenerator & Rule-Based Test Synthesis Tests")
class ApiTestGeneratorTest {

    private OpenApiParser parser;
    private ApiTestGenerator generator;

    @BeforeEach
    void setUp() {
        parser = new OpenApiParser();
        generator = new ApiTestGenerator(GenerationConfig.builder().seed(42L).build());
    }

    @Test
    @DisplayName("1. Valid string generation respects minLength and maxLength")
    void testValidStringGeneration() {
        ApiSchema schema = ApiSchema.ofType(SchemaType.STRING);
        schema.setMinLength(5);
        schema.setMaxLength(10);

        ValidInputGenerator validGen = generator.getValidInputGenerator();
        Object val = validGen.generateValidValue(schema, 0, GenerationStrategy.SCHEMA_VALID_FULL);

        assertNotNull(val);
        assertInstanceOf(String.class, val);
        String s = (String) val;
        assertTrue(s.length() >= 5, "Length should be >= minLength (5), was: " + s.length());
        assertTrue(s.length() <= 10, "Length should be <= maxLength (10), was: " + s.length());
    }

    @Test
    @DisplayName("2. Valid email generation creates syntactically valid email")
    void testValidEmailGeneration() {
        ApiSchema schema = ApiSchema.ofType(SchemaType.STRING);
        schema.setFormat("email");

        ValidInputGenerator validGen = generator.getValidInputGenerator();
        Object val = validGen.generateValidValue(schema, 0, GenerationStrategy.SCHEMA_VALID_FULL);

        assertNotNull(val);
        assertInstanceOf(String.class, val);
        String email = (String) val;
        assertTrue(email.contains("@") && email.contains("."), "Generated email must contain '@' and '.', was: " + email);
    }

    @Test
    @DisplayName("3. Valid integer generation falls within bounds")
    void testValidIntegerGeneration() {
        ApiSchema schema = ApiSchema.ofType(SchemaType.INTEGER);
        schema.setMinimum(BigDecimal.valueOf(10));
        schema.setMaximum(BigDecimal.valueOf(25));

        ValidInputGenerator validGen = generator.getValidInputGenerator();
        Object val = validGen.generateValidValue(schema, 0, GenerationStrategy.SCHEMA_VALID_FULL);

        assertNotNull(val);
        assertInstanceOf(Long.class, val);
        long n = (Long) val;
        assertTrue(n >= 10 && n <= 25, "Value should be between 10 and 25 inclusive, was: " + n);
    }

    @Test
    @DisplayName("4. Valid number decimal generation falls within decimal bounds")
    void testValidNumberGeneration() {
        ApiSchema schema = ApiSchema.ofType(SchemaType.NUMBER);
        schema.setMinimum(BigDecimal.valueOf(1.5));
        schema.setMaximum(BigDecimal.valueOf(4.5));

        ValidInputGenerator validGen = generator.getValidInputGenerator();
        Object val = validGen.generateValidValue(schema, 0, GenerationStrategy.SCHEMA_VALID_FULL);

        assertNotNull(val);
        assertInstanceOf(BigDecimal.class, val);
        BigDecimal d = (BigDecimal) val;
        assertTrue(d.compareTo(BigDecimal.valueOf(1.5)) >= 0);
        assertTrue(d.compareTo(BigDecimal.valueOf(4.5)) <= 0);
    }

    @Test
    @DisplayName("5. Boolean generation produces true or false")
    void testBooleanGeneration() {
        ApiSchema schema = ApiSchema.ofType(SchemaType.BOOLEAN);
        ValidInputGenerator validGen = generator.getValidInputGenerator();
        Object val = validGen.generateValidValue(schema, 0, GenerationStrategy.SCHEMA_VALID_FULL);

        assertNotNull(val);
        assertInstanceOf(Boolean.class, val);
    }

    @Test
    @DisplayName("6. Enum generation strictly picks from declared enum values")
    void testEnumGeneration() {
        ApiSchema schema = ApiSchema.ofType(SchemaType.STRING);
        schema.setEnumValues(List.of("STANDARD", "PREMIUM", "VIP"));

        ValidInputGenerator validGen = generator.getValidInputGenerator();
        for (int i = 0; i < 10; i++) {
            Object val = validGen.generateValidValue(schema, 0, GenerationStrategy.SCHEMA_VALID_FULL);
            assertTrue(List.of("STANDARD", "PREMIUM", "VIP").contains(val.toString()));
        }
    }

    @Test
    @DisplayName("7. Nested object generation populates nested structure recursively")
    void testNestedObjectGeneration() {
        ApiSchema root = ApiSchema.ofType(SchemaType.OBJECT);
        ApiSchema child = ApiSchema.ofType(SchemaType.OBJECT);
        child.addProperty("street", ApiSchema.ofType(SchemaType.STRING));
        child.addRequiredProperty("street");
        root.addProperty("address", child);
        root.addRequiredProperty("address");

        ValidInputGenerator validGen = generator.getValidInputGenerator();
        Object val = validGen.generateValidValue(root, 0, GenerationStrategy.SCHEMA_VALID_FULL);

        assertNotNull(val);
        assertInstanceOf(Map.class, val);
        Map<?, ?> map = (Map<?, ?>) val;
        assertTrue(map.containsKey("address"));
        assertInstanceOf(Map.class, map.get("address"));
        Map<?, ?> childMap = (Map<?, ?>) map.get("address");
        assertTrue(childMap.containsKey("street"));
    }

    @Test
    @DisplayName("8. Array generation produces list satisfying item schema and count")
    void testArrayGeneration() {
        ApiSchema arraySchema = ApiSchema.ofType(SchemaType.ARRAY);
        arraySchema.setMinItems(2);
        arraySchema.setMaxItems(5);
        arraySchema.setItems(ApiSchema.ofType(SchemaType.INTEGER));

        ValidInputGenerator validGen = generator.getValidInputGenerator();
        Object val = validGen.generateValidValue(arraySchema, 0, GenerationStrategy.SCHEMA_VALID_FULL);

        assertNotNull(val);
        assertInstanceOf(List.class, val);
        List<?> list = (List<?>) val;
        assertTrue(list.size() >= 2 && list.size() <= 5);
        for (Object item : list) {
            assertInstanceOf(Long.class, item);
        }
    }

    @Test
    @DisplayName("9. Required fields are always present in valid test cases")
    void testRequiredFieldHandling() {
        String yaml = """
                openapi: 3.0.0
                info: { title: User API, version: 1.0 }
                paths:
                  /users:
                    post:
                      requestBody:
                        required: true
                        content:
                          application/json:
                            schema:
                              type: object
                              required: [id, username]
                              properties:
                                id: { type: integer }
                                username: { type: string }
                                bio: { type: string }
                      responses:
                        '201': { description: Created }
                """;

        ParsedApiSpecification spec = parser.parse(yaml);
        List<ApiTestCase> cases = generator.generateForEndpoint(spec.getEndpoints().get(0));

        // Find valid test cases
        List<ApiTestCase> validCases = cases.stream()
                .filter(ApiTestCase::isExpectedValid)
                .toList();

        assertFalse(validCases.isEmpty());
        for (ApiTestCase tc : validCases) {
            assertInstanceOf(Map.class, tc.requestBody());
            Map<?, ?> body = (Map<?, ?>) tc.requestBody();
            assertTrue(body.containsKey("id"), "Valid case must contain required field 'id'");
            assertTrue(body.containsKey("username"), "Valid case must contain required field 'username'");
        }
    }

    @Test
    @DisplayName("10. Optional fields are included in full strategy and omitted in minimal strategy")
    void testOptionalFieldInclusionAndOmission() {
        String yaml = """
                openapi: 3.0.0
                info: { title: User API, version: 1.0 }
                paths:
                  /users:
                    post:
                      requestBody:
                        required: true
                        content:
                          application/json:
                            schema:
                              type: object
                              required: [id]
                              properties:
                                id: { type: integer }
                                optionalNotes: { type: string }
                      responses:
                        '201': { description: Created }
                """;

        ParsedApiSpecification spec = parser.parse(yaml);
        List<ApiTestCase> cases = generator.generateForEndpoint(spec.getEndpoints().get(0));

        ApiTestCase fullCase = cases.stream()
                .filter(tc -> tc.strategy() == GenerationStrategy.SCHEMA_VALID_FULL)
                .findFirst().orElseThrow();
        Map<?, ?> fullBody = (Map<?, ?>) fullCase.requestBody();
        assertTrue(fullBody.containsKey("optionalNotes"), "Full strategy must include optional fields");

        ApiTestCase minimalCase = cases.stream()
                .filter(tc -> tc.strategy() == GenerationStrategy.SCHEMA_VALID_MINIMAL)
                .findFirst().orElseThrow();
        Map<?, ?> minBody = (Map<?, ?>) minimalCase.requestBody();
        assertFalse(minBody.containsKey("optionalNotes"), "Minimal strategy must omit optional fields");
    }

    @Test
    @DisplayName("11. Missing required field negative test generation")
    void testMissingRequiredFieldGeneration() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Order API, version: 1.0 }
                paths:
                  /orders:
                    post:
                      requestBody:
                        required: true
                        content:
                          application/json:
                            schema:
                              type: object
                              required: [orderId, customerId]
                              properties:
                                orderId: { type: string }
                                customerId: { type: string }
                                note: { type: string }
                      responses:
                        '201': { description: Created }
                """;

        ParsedApiSpecification spec = parser.parse(yaml);
        List<ApiTestCase> cases = generator.generateForEndpoint(spec.getEndpoints().get(0));

        List<ApiTestCase> missingCases = cases.stream()
                .filter(tc -> tc.strategy() == GenerationStrategy.MISSING_REQUIRED_FIELD)
                .toList();

        assertEquals(2, missingCases.size(), "Should produce a negative test for each omitted required field");
        Set<String> targeted = new HashSet<>();
        for (ApiTestCase tc : missingCases) {
            assertEquals(TestCategory.INVALID, tc.category());
            Map<?, ?> body = (Map<?, ?>) tc.requestBody();
            assertFalse(body.containsKey(tc.targetedProperty()), "Targeted property must be omitted from body");
            targeted.add(tc.targetedProperty());
        }
        assertTrue(targeted.contains("orderId"));
        assertTrue(targeted.contains("customerId"));
    }

    @Test
    @DisplayName("12. Type mismatch negative test generation")
    void testTypeMismatchGeneration() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Math API, version: 1.0 }
                paths:
                  /compute:
                    post:
                      requestBody:
                        required: true
                        content:
                          application/json:
                            schema:
                              type: object
                              properties:
                                count: { type: integer }
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification spec = parser.parse(yaml);
        List<ApiTestCase> cases = generator.generateForEndpoint(spec.getEndpoints().get(0));

        ApiTestCase mismatch = cases.stream()
                .filter(tc -> tc.strategy() == GenerationStrategy.TYPE_MISMATCH && "count".equals(tc.targetedProperty()))
                .findFirst().orElseThrow();

        assertEquals(TestCategory.INVALID, mismatch.category());
        Map<?, ?> body = (Map<?, ?>) mismatch.requestBody();
        assertFalse(body.get("count") instanceof Number, "Expected non-numeric type mismatch value for count");
    }

    @Test
    @DisplayName("13. Invalid format negative test generation")
    void testInvalidFormatGeneration() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Auth API, version: 1.0 }
                paths:
                  /register:
                    post:
                      requestBody:
                        required: true
                        content:
                          application/json:
                            schema:
                              type: object
                              properties:
                                email: { type: string, format: email }
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification spec = parser.parse(yaml);
        List<ApiTestCase> cases = generator.generateForEndpoint(spec.getEndpoints().get(0));

        ApiTestCase invalidFmt = cases.stream()
                .filter(tc -> tc.strategy() == GenerationStrategy.INVALID_FORMAT && "email".equals(tc.targetedProperty()))
                .findFirst().orElseThrow();

        assertEquals(TestCategory.INVALID, invalidFmt.category());
        Map<?, ?> body = (Map<?, ?>) invalidFmt.requestBody();
        String val = (String) body.get("email");
        assertFalse(val.contains("@") && val.contains("."), "Invalid format should violate email syntax");
    }

    @Test
    @DisplayName("14. Invalid enum negative test generation")
    void testInvalidEnumGeneration() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Role API, version: 1.0 }
                paths:
                  /roles:
                    post:
                      requestBody:
                        required: true
                        content:
                          application/json:
                            schema:
                              type: object
                              properties:
                                role: { type: string, enum: [ADMIN, USER] }
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification spec = parser.parse(yaml);
        List<ApiTestCase> cases = generator.generateForEndpoint(spec.getEndpoints().get(0));

        ApiTestCase invalidEnum = cases.stream()
                .filter(tc -> tc.strategy() == GenerationStrategy.INVALID_ENUM && "role".equals(tc.targetedProperty()))
                .findFirst().orElseThrow();

        assertEquals(TestCategory.INVALID, invalidEnum.category());
        Map<?, ?> body = (Map<?, ?>) invalidEnum.requestBody();
        assertFalse(List.of("ADMIN", "USER").contains(body.get("role")));
    }

    @Test
    @DisplayName("15. Numeric boundary value test generation (minimum and maximum)")
    void testNumericBoundaryGeneration() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Range API, version: 1.0 }
                paths:
                  /range:
                    post:
                      requestBody:
                        required: true
                        content:
                          application/json:
                            schema:
                              type: object
                              properties:
                                score: { type: integer, minimum: 1, maximum: 100 }
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification spec = parser.parse(yaml);
        List<ApiTestCase> cases = generator.generateForEndpoint(spec.getEndpoints().get(0));

        ApiTestCase minBoundary = cases.stream()
                .filter(tc -> tc.strategy() == GenerationStrategy.NUMERIC_MIN_BOUNDARY && "score".equals(tc.targetedProperty()))
                .findFirst().orElseThrow();
        assertEquals(TestCategory.BOUNDARY, minBoundary.category());
        assertEquals(1L, ((Map<?, ?>) minBoundary.requestBody()).get("score"));

        ApiTestCase maxBoundary = cases.stream()
                .filter(tc -> tc.strategy() == GenerationStrategy.NUMERIC_MAX_BOUNDARY && "score".equals(tc.targetedProperty()))
                .findFirst().orElseThrow();
        assertEquals(TestCategory.BOUNDARY, maxBoundary.category());
        assertEquals(100L, ((Map<?, ?>) maxBoundary.requestBody()).get("score"));
    }

    @Test
    @DisplayName("16. String length boundary generation (minLength and maxLength)")
    void testStringLengthBoundaries() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Text API, version: 1.0 }
                paths:
                  /text:
                    post:
                      requestBody:
                        required: true
                        content:
                          application/json:
                            schema:
                              type: object
                              properties:
                                code: { type: string, minLength: 3, maxLength: 8 }
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification spec = parser.parse(yaml);
        List<ApiTestCase> cases = generator.generateForEndpoint(spec.getEndpoints().get(0));

        ApiTestCase minLen = cases.stream()
                .filter(tc -> tc.strategy() == GenerationStrategy.STRING_MIN_LENGTH_BOUNDARY && "code".equals(tc.targetedProperty()))
                .findFirst().orElseThrow();
        assertEquals(3, ((String) ((Map<?, ?>) minLen.requestBody()).get("code")).length());

        ApiTestCase maxLen = cases.stream()
                .filter(tc -> tc.strategy() == GenerationStrategy.STRING_MAX_LENGTH_BOUNDARY && "code".equals(tc.targetedProperty()))
                .findFirst().orElseThrow();
        assertEquals(8, ((String) ((Map<?, ?>) maxLen.requestBody()).get("code")).length());
    }

    @Test
    @DisplayName("17. Array size boundary generation (empty array and item bounds)")
    void testArraySizeBoundaries() {
        String yaml = """
                openapi: 3.0.0
                info: { title: List API, version: 1.0 }
                paths:
                  /tags:
                    post:
                      requestBody:
                        required: true
                        content:
                          application/json:
                            schema:
                              type: object
                              properties:
                                items:
                                  type: array
                                  minItems: 2
                                  maxItems: 4
                                  items: { type: string }
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification spec = parser.parse(yaml);
        List<ApiTestCase> cases = generator.generateForEndpoint(spec.getEndpoints().get(0));

        ApiTestCase emptyArray = cases.stream()
                .filter(tc -> tc.strategy() == GenerationStrategy.ARRAY_EMPTY_BOUNDARY)
                .findFirst().orElseThrow();
        assertEquals(0, ((List<?>) ((Map<?, ?>) emptyArray.requestBody()).get("items")).size());

        ApiTestCase minItems = cases.stream()
                .filter(tc -> tc.strategy() == GenerationStrategy.ARRAY_MIN_ITEMS_BOUNDARY)
                .findFirst().orElseThrow();
        assertEquals(2, ((List<?>) ((Map<?, ?>) minItems.requestBody()).get("items")).size());
    }

    @Test
    @DisplayName("18. Exclusive numeric constraints respected in boundary calculations")
    void testExclusiveNumericConstraints() {
        ApiSchema schema = ApiSchema.ofType(SchemaType.INTEGER);
        schema.setMinimum(BigDecimal.valueOf(10));
        schema.setExclusiveMinimum(true);

        BoundaryValueGenerator boundaryGen = generator.getBoundaryValueGenerator();
        Number minBound = boundaryGen.generateNumericMinBoundary(schema);
        assertEquals(11L, minBound.longValue(), "Exclusive minimum 10 must result in boundary 11 for integer");
    }

    @Test
    @DisplayName("19. Circular schema handling does not trigger infinite recursion")
    void testCircularSchemaHandling() {
        ApiSchema parent = ApiSchema.ofType(SchemaType.OBJECT);
        parent.addProperty("id", ApiSchema.ofType(SchemaType.INTEGER));
        ApiSchema childRef = ApiSchema.circular("#/components/schemas/Node", SchemaType.OBJECT);
        parent.addProperty("child", childRef);

        ValidInputGenerator validGen = generator.getValidInputGenerator();
        Object val = assertDoesNotThrow(() -> validGen.generateValidValue(parent, 0, GenerationStrategy.SCHEMA_VALID_FULL));
        assertNotNull(val);
        assertInstanceOf(Map.class, val);
    }

    @Test
    @DisplayName("20. Maximum generation limits per endpoint and per suite are strictly enforced")
    void testGenerationLimits() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Big API, version: 1.0 }
                paths:
                  /ep1: { get: { responses: { '200': {} } } }
                  /ep2: { get: { responses: { '200': {} } } }
                  /ep3: { get: { responses: { '200': {} } } }
                """;

        GenerationConfig limitedConfig = GenerationConfig.builder()
                .maxTestCasesPerEndpoint(2)
                .maxTotalGeneratedCases(4)
                .build();
        ApiTestGenerator limitedGen = new ApiTestGenerator(limitedConfig);

        ParsedApiSpecification spec = parser.parse(yaml);
        List<ApiTestCase> suite = limitedGen.generateSuite(spec);

        assertTrue(suite.size() <= 4, "Total generated cases must not exceed maxTotalGeneratedCases");
    }

    @Test
    @DisplayName("21. Duplicate prevention guarantees unique test-case signatures per endpoint")
    void testDuplicatePrevention() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Dupe API, version: 1.0 }
                paths:
                  /items:
                    get:
                      parameters:
                        - name: status
                          in: query
                          schema: { type: string, enum: [A, B] }
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification spec = parser.parse(yaml);
        List<ApiTestCase> cases = generator.generateForEndpoint(spec.getEndpoints().get(0));

        Set<String> seen = new HashSet<>();
        for (ApiTestCase tc : cases) {
            String sig = tc.category() + "|" + tc.strategy() + "|" + tc.targetedProperty() + "|" + tc.queryParameters();
            assertTrue(seen.add(sig), "Duplicate test case detected: " + sig);
        }
    }

    @Test
    @DisplayName("22. Deterministic generation using identical random seeds")
    void testDeterministicSeededGeneration() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Seed API, version: 1.0 }
                paths:
                  /randomized:
                    post:
                      requestBody:
                        required: true
                        content:
                          application/json:
                            schema:
                              type: object
                              properties:
                                token: { type: string, format: uuid }
                                score: { type: integer, minimum: 1, maximum: 500 }
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification spec = parser.parse(yaml);
        ApiEndpoint endpoint = spec.getEndpoints().get(0);

        ApiTestGenerator gen1 = new ApiTestGenerator(GenerationConfig.builder().seed(999L).build());
        List<ApiTestCase> suite1 = gen1.generateForEndpoint(endpoint);

        ApiTestGenerator gen2 = new ApiTestGenerator(GenerationConfig.builder().seed(999L).build());
        List<ApiTestCase> suite2 = gen2.generateForEndpoint(endpoint);

        assertEquals(suite1.size(), suite2.size());
        for (int i = 0; i < suite1.size(); i++) {
            assertEquals(suite1.get(i).requestBody(), suite2.get(i).requestBody());
            assertEquals(suite1.get(i).strategy(), suite2.get(i).strategy());
        }
    }

    @Test
    @DisplayName("23. Different seeds produce distinct randomized outputs")
    void testDifferentSeedsProduceDifferentOutputs() {
        ApiSchema schema = ApiSchema.ofType(SchemaType.STRING);
        schema.setFormat("email");

        ValidInputGenerator gen1 = new ValidInputGenerator(GenerationConfig.defaultConfig(), new Random(101L));
        Object email1 = gen1.generateValidValue(schema, 0, GenerationStrategy.SCHEMA_VALID_FULL);

        ValidInputGenerator gen2 = new ValidInputGenerator(GenerationConfig.defaultConfig(), new Random(999999L));
        Object email2 = gen2.generateValidValue(schema, 0, GenerationStrategy.SCHEMA_VALID_FULL);

        assertNotEquals(email1, email2, "Different seeds should produce different randomized emails");
    }

    @Test
    @DisplayName("24. Multiple endpoints generation produces test cases for all operations")
    void testMultipleEndpointsGeneration() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Multi API, version: 1.0 }
                paths:
                  /users:
                    get: { responses: { '200': {} } }
                    post: { responses: { '201': {} } }
                  /products:
                    get: { responses: { '200': {} } }
                """;

        ParsedApiSpecification spec = parser.parse(yaml);
        List<ApiTestCase> suite = generator.generateSuite(spec);

        Set<String> identifiers = new HashSet<>();
        for (ApiTestCase tc : suite) {
            identifiers.add(tc.endpointIdentifier());
        }

        assertTrue(identifiers.contains("GET /users"));
        assertTrue(identifiers.contains("POST /users"));
        assertTrue(identifiers.contains("GET /products"));
    }

    @Test
    @DisplayName("25. Query and path parameter generation correctly populates parameter maps")
    void testQueryAndPathParameterGeneration() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Params API, version: 1.0 }
                paths:
                  /orgs/{orgId}/repos:
                    get:
                      parameters:
                        - name: orgId
                          in: path
                          required: true
                          schema: { type: string }
                        - name: type
                          in: query
                          required: true
                          schema: { type: string, enum: [all, public, private] }
                        - name: page
                          in: query
                          required: false
                          schema: { type: integer, default: 1 }
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification spec = parser.parse(yaml);
        List<ApiTestCase> cases = generator.generateForEndpoint(spec.getEndpoints().get(0));

        ApiTestCase fullCase = cases.stream()
                .filter(tc -> tc.strategy() == GenerationStrategy.SCHEMA_VALID_FULL)
                .findFirst().orElseThrow();

        assertTrue(fullCase.pathParameters().containsKey("orgId"));
        assertTrue(fullCase.queryParameters().containsKey("type"));
        assertTrue(fullCase.queryParameters().containsKey("page"));
    }
}

