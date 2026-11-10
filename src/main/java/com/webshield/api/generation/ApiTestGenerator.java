package com.webshield.api.generation;

import com.webshield.api.models.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Main coordinator for rule-based, schema-aware automated API test-case generation.
 */
@Component
public class ApiTestGenerator {

    private static final Logger log = LoggerFactory.getLogger(ApiTestGenerator.class);

    private final GenerationConfig config;
    private final Random random;
    private final ValidInputGenerator validGen;
    private final InvalidInputGenerator invalidGen;
    private final BoundaryValueGenerator boundaryGen;
    private final TestCaseFactory testCaseFactory;

    public ApiTestGenerator() {
        this(GenerationConfig.defaultConfig());
    }

    public ApiTestGenerator(GenerationConfig config) {
        this.config = config != null ? config : GenerationConfig.defaultConfig();
        this.random = new Random(this.config.getSeed());
        this.validGen = new ValidInputGenerator(this.config, this.random);
        this.invalidGen = new InvalidInputGenerator(this.validGen, this.config, this.random);
        this.boundaryGen = new BoundaryValueGenerator(this.validGen, this.config);
        this.testCaseFactory = new TestCaseFactory();
    }

    /**
     * Generates a comprehensive test suite across all endpoints in a parsed specification.
     */
    public List<ApiTestCase> generateSuite(ParsedApiSpecification specification) {
        if (specification == null || specification.getEndpoints().isEmpty()) {
            return List.of();
        }

        List<ApiTestCase> suite = new ArrayList<>();
        testCaseFactory.reset();

        for (ApiEndpoint endpoint : specification.getEndpoints()) {
            if (suite.size() >= config.getMaxTotalGeneratedCases()) {
                log.info("Reached maximum total generated cases limit: {}", config.getMaxTotalGeneratedCases());
                break;
            }
            List<ApiTestCase> endpointCases = generateForEndpoint(endpoint);
            for (ApiTestCase tc : endpointCases) {
                if (suite.size() < config.getMaxTotalGeneratedCases()) {
                    suite.add(tc);
                } else {
                    break;
                }
            }
        }

        log.info("Generated {} total test cases across {} endpoints", suite.size(), specification.getEndpointsCount());
        return Collections.unmodifiableList(suite);
    }

    /**
     * Generates test cases for a single endpoint according to configuration.
     */
    public List<ApiTestCase> generateForEndpoint(ApiEndpoint endpoint) {
        if (endpoint == null) {
            return List.of();
        }

        List<ApiTestCase> result = new ArrayList<>();
        Set<String> deduplicationSet = new HashSet<>();

        // Generate baseline valid parameter sets
        Map<String, Object> baselinePathParams = buildBaselinePathParams(endpoint);
        Map<String, Object> fullQueryParams = buildBaselineQueryParams(endpoint, true);
        Map<String, Object> minimalQueryParams = buildBaselineQueryParams(endpoint, false);
        Map<String, String> headers = buildBaselineHeaders(endpoint);
        Map<String, String> cookies = buildBaselineCookies(endpoint);

        ApiSchema bodySchema = endpoint.hasRequestBody() ? endpoint.getRequestBody().getJsonSchema() : null;

        // =========================================================================
        // 1. Valid Test Cases
        // =========================================================================
        if (config.isEnableValid()) {
            // Full valid
            Object fullBody = bodySchema != null
                    ? validGen.generateValidValue(bodySchema, 0, GenerationStrategy.SCHEMA_VALID_FULL)
                    : null;
            addTestCaseIfUnique(result, deduplicationSet, testCaseFactory.createTestCase(
                    endpoint, TestCategory.VALID, GenerationStrategy.SCHEMA_VALID_FULL,
                    baselinePathParams, fullQueryParams, headers, cookies,
                    fullBody, "application/json", config.getSeed(),
                    "Full valid request with all optional and required inputs populated",
                    null, null, null
            ));

            // Minimal valid (required only)
            if (hasOptionalElements(endpoint, bodySchema)) {
                Object minimalBody = bodySchema != null
                        ? validGen.generateValidValue(bodySchema, 0, GenerationStrategy.SCHEMA_VALID_MINIMAL)
                        : null;
                addTestCaseIfUnique(result, deduplicationSet, testCaseFactory.createTestCase(
                        endpoint, TestCategory.VALID, GenerationStrategy.SCHEMA_VALID_MINIMAL,
                        baselinePathParams, minimalQueryParams, headers, cookies,
                        minimalBody, "application/json", config.getSeed(),
                        "Minimal valid request containing only required parameters and fields",
                        null, null, null
                ));
            }
        }

        // =========================================================================
        // 2. Negative / Invalid Test Cases
        // =========================================================================
        if (config.isEnableInvalid()) {
            // Parameter-level invalid tests
            generateInvalidParameterTests(endpoint, baselinePathParams, fullQueryParams, headers, cookies, bodySchema, result, deduplicationSet);

            // Body-level invalid tests
            if (bodySchema != null) {
                generateInvalidBodyTests(endpoint, baselinePathParams, fullQueryParams, headers, cookies, bodySchema, result, deduplicationSet);
            }
        }

        // =========================================================================
        // 3. Boundary Value Test Cases
        // =========================================================================
        if (config.isEnableBoundary()) {
            // Parameter-level boundary tests
            generateBoundaryParameterTests(endpoint, baselinePathParams, fullQueryParams, headers, cookies, bodySchema, result, deduplicationSet);

            // Body-level boundary tests
            if (bodySchema != null) {
                generateBoundaryBodyTests(endpoint, baselinePathParams, fullQueryParams, headers, cookies, bodySchema, result, deduplicationSet);
            }
        }

        return Collections.unmodifiableList(result);
    }

    private void generateInvalidParameterTests(ApiEndpoint endpoint,
                                               Map<String, Object> pathParams,
                                               Map<String, Object> queryParams,
                                               Map<String, String> headers,
                                               Map<String, String> cookies,
                                               ApiSchema bodySchema,
                                               List<ApiTestCase> result,
                                               Set<String> dedup) {
        Object validBody = bodySchema != null ? validGen.generateValidValue(bodySchema, 0, GenerationStrategy.SCHEMA_VALID_FULL) : null;

        for (ApiParameter param : endpoint.getParameters()) {
            if (result.size() >= config.getMaxTestCasesPerEndpoint()) break;

            String pName = param.getName();
            ParameterLocation pLoc = param.getLocation();
            ApiSchema pSchema = param.getSchema();

            // 1. Missing required query / header parameter
            if (param.isRequired() && (pLoc == ParameterLocation.QUERY || pLoc == ParameterLocation.HEADER)) {
                Map<String, Object> mutatedQueries = new LinkedHashMap<>(queryParams);
                Map<String, String> mutatedHeaders = new LinkedHashMap<>(headers);
                if (pLoc == ParameterLocation.QUERY) mutatedQueries.remove(pName);
                if (pLoc == ParameterLocation.HEADER) mutatedHeaders.remove(pName);

                addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                        endpoint, TestCategory.INVALID, GenerationStrategy.MISSING_REQUIRED_FIELD,
                        pathParams, mutatedQueries, mutatedHeaders, cookies, validBody, "application/json",
                        config.getSeed(), "Missing required " + pLoc.getValue() + " parameter: " + pName,
                        pName, "required", null
                ));
            }

            // 2. Type mismatch on parameter
            if (pSchema != null && pLoc != ParameterLocation.PATH) {
                Object mismatch = invalidGen.generateTypeMismatch(pSchema);
                Map<String, Object> mutatedQueries = new LinkedHashMap<>(queryParams);
                mutatedQueries.put(pName, mismatch);

                addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                        endpoint, TestCategory.INVALID, GenerationStrategy.TYPE_MISMATCH,
                        pathParams, mutatedQueries, headers, cookies, validBody, "application/json",
                        config.getSeed(), "Type mismatch for parameter: " + pName,
                        pName, "type: " + pSchema.getType(), null
                ));
            }

            // 3. Invalid enum on parameter
            if (pSchema != null && !pSchema.getEnumValues().isEmpty() && pLoc != ParameterLocation.PATH) {
                String invalidEnum = invalidGen.generateInvalidEnum(pSchema);
                Map<String, Object> mutatedQueries = new LinkedHashMap<>(queryParams);
                mutatedQueries.put(pName, invalidEnum);

                addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                        endpoint, TestCategory.INVALID, GenerationStrategy.INVALID_ENUM,
                        pathParams, mutatedQueries, headers, cookies, validBody, "application/json",
                        config.getSeed(), "Invalid enum value for parameter: " + pName,
                        pName, "enum: " + pSchema.getEnumValues(), null
                ));
            }

            // 4. Invalid format on parameter
            if (pSchema != null && pSchema.getFormat() != null && !pSchema.getFormat().isBlank() && pLoc != ParameterLocation.PATH) {
                String invalidFmt = invalidGen.generateInvalidFormat(pSchema);
                Map<String, Object> mutatedQueries = new LinkedHashMap<>(queryParams);
                mutatedQueries.put(pName, invalidFmt);

                addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                        endpoint, TestCategory.INVALID, GenerationStrategy.INVALID_FORMAT,
                        pathParams, mutatedQueries, headers, cookies, validBody, "application/json",
                        config.getSeed(), "Invalid format for parameter " + pName + " (expected " + pSchema.getFormat() + ")",
                        pName, "format: " + pSchema.getFormat(), null
                ));
            }
        }
    }

    private void generateInvalidBodyTests(ApiEndpoint endpoint,
                                          Map<String, Object> pathParams,
                                          Map<String, Object> queryParams,
                                          Map<String, String> headers,
                                          Map<String, String> cookies,
                                          ApiSchema bodySchema,
                                          List<ApiTestCase> result,
                                          Set<String> dedup) {
        if (!bodySchema.isObject()) return;

        Map<String, ApiSchema> props = bodySchema.getProperties();
        if (props == null || props.isEmpty()) return;

        Map<String, Object> validBase = (Map<String, Object>) validGen.generateValidValue(bodySchema, 0, GenerationStrategy.SCHEMA_VALID_FULL);

        // 1. Missing required field
        for (String reqProp : bodySchema.getRequiredProperties()) {
            if (result.size() >= config.getMaxTestCasesPerEndpoint()) break;
            Map<String, Object> mutated = new LinkedHashMap<>(validBase);
            mutated.remove(reqProp);

            addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                    endpoint, TestCategory.INVALID, GenerationStrategy.MISSING_REQUIRED_FIELD,
                    pathParams, queryParams, headers, cookies, mutated, "application/json",
                    config.getSeed(), "Omission of required body property: " + reqProp,
                    reqProp, "required", null
            ));
        }

        // 2. Type mismatch for body properties
        for (Map.Entry<String, ApiSchema> entry : props.entrySet()) {
            if (result.size() >= config.getMaxTestCasesPerEndpoint()) break;
            String propName = entry.getKey();
            ApiSchema propSchema = entry.getValue();

            Map<String, Object> mutated = new LinkedHashMap<>(validBase);
            mutated.put(propName, invalidGen.generateTypeMismatch(propSchema));

            addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                    endpoint, TestCategory.INVALID, GenerationStrategy.TYPE_MISMATCH,
                    pathParams, queryParams, headers, cookies, mutated, "application/json",
                    config.getSeed(), "Type mismatch on property: " + propName,
                    propName, "type: " + propSchema.getType(), null
            ));
        }

        // 3. Invalid enum on body property
        for (Map.Entry<String, ApiSchema> entry : props.entrySet()) {
            if (result.size() >= config.getMaxTestCasesPerEndpoint()) break;
            String propName = entry.getKey();
            ApiSchema propSchema = entry.getValue();

            if (!propSchema.getEnumValues().isEmpty()) {
                Map<String, Object> mutated = new LinkedHashMap<>(validBase);
                mutated.put(propName, invalidGen.generateInvalidEnum(propSchema));

                addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                        endpoint, TestCategory.INVALID, GenerationStrategy.INVALID_ENUM,
                        pathParams, queryParams, headers, cookies, mutated, "application/json",
                        config.getSeed(), "Invalid enum value for property: " + propName,
                        propName, "enum: " + propSchema.getEnumValues(), null
                ));
            }
        }

        // 4. Invalid format on body property
        for (Map.Entry<String, ApiSchema> entry : props.entrySet()) {
            if (result.size() >= config.getMaxTestCasesPerEndpoint()) break;
            String propName = entry.getKey();
            ApiSchema propSchema = entry.getValue();

            if (propSchema.getFormat() != null && !propSchema.getFormat().isBlank()) {
                Map<String, Object> mutated = new LinkedHashMap<>(validBase);
                mutated.put(propName, invalidGen.generateInvalidFormat(propSchema));

                addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                        endpoint, TestCategory.INVALID, GenerationStrategy.INVALID_FORMAT,
                        pathParams, queryParams, headers, cookies, mutated, "application/json",
                        config.getSeed(), "Invalid format for property " + propName + " (" + propSchema.getFormat() + ")",
                        propName, "format: " + propSchema.getFormat(), null
                ));
            }
        }

        // 5. String length exceeded on body property
        for (Map.Entry<String, ApiSchema> entry : props.entrySet()) {
            if (result.size() >= config.getMaxTestCasesPerEndpoint()) break;
            String propName = entry.getKey();
            ApiSchema propSchema = entry.getValue();

            if (propSchema.getMaxLength() != null) {
                Map<String, Object> mutated = new LinkedHashMap<>(validBase);
                mutated.put(propName, invalidGen.generateStringLengthExceeded(propSchema));

                addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                        endpoint, TestCategory.INVALID, GenerationStrategy.STRING_LENGTH_EXCEEDED,
                        pathParams, queryParams, headers, cookies, mutated, "application/json",
                        config.getSeed(), "String exceeds maxLength for property: " + propName,
                        propName, "maxLength: " + propSchema.getMaxLength(), null
                ));
            }
        }

        // 6. Null injection into non-nullable required property
        for (String reqProp : bodySchema.getRequiredProperties()) {
            if (result.size() >= config.getMaxTestCasesPerEndpoint()) break;
            ApiSchema propSchema = props.get(reqProp);
            if (propSchema != null && !propSchema.isNullable()) {
                Map<String, Object> mutated = new LinkedHashMap<>(validBase);
                mutated.put(reqProp, null);

                addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                        endpoint, TestCategory.INVALID, GenerationStrategy.NULL_INJECTION,
                        pathParams, queryParams, headers, cookies, mutated, "application/json",
                        config.getSeed(), "Null injection into non-nullable required property: " + reqProp,
                        reqProp, "nullable: false", null
                ));
            }
        }
    }

    private void generateBoundaryParameterTests(ApiEndpoint endpoint,
                                                Map<String, Object> pathParams,
                                                Map<String, Object> queryParams,
                                                Map<String, String> headers,
                                                Map<String, String> cookies,
                                                ApiSchema bodySchema,
                                                List<ApiTestCase> result,
                                                Set<String> dedup) {
        Object validBody = bodySchema != null ? validGen.generateValidValue(bodySchema, 0, GenerationStrategy.SCHEMA_VALID_FULL) : null;

        for (ApiParameter param : endpoint.getParameters()) {
            if (result.size() >= config.getMaxTestCasesPerEndpoint()) break;
            ApiSchema pSchema = param.getSchema();
            if (pSchema == null || param.getLocation() == ParameterLocation.PATH) continue;

            String pName = param.getName();

            // Numeric min and max
            if (pSchema.getMinimum() != null) {
                Map<String, Object> mutated = new LinkedHashMap<>(queryParams);
                mutated.put(pName, boundaryGen.generateNumericMinBoundary(pSchema));

                addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                        endpoint, TestCategory.BOUNDARY, GenerationStrategy.NUMERIC_MIN_BOUNDARY,
                        pathParams, mutated, headers, cookies, validBody, "application/json",
                        config.getSeed(), "Numeric minimum boundary for parameter: " + pName,
                        pName, "minimum: " + pSchema.getMinimum(), null
                ));
            }

            if (pSchema.getMaximum() != null) {
                Map<String, Object> mutated = new LinkedHashMap<>(queryParams);
                mutated.put(pName, boundaryGen.generateNumericMaxBoundary(pSchema));

                addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                        endpoint, TestCategory.BOUNDARY, GenerationStrategy.NUMERIC_MAX_BOUNDARY,
                        pathParams, mutated, headers, cookies, validBody, "application/json",
                        config.getSeed(), "Numeric maximum boundary for parameter: " + pName,
                        pName, "maximum: " + pSchema.getMaximum(), null
                ));
            }
        }
    }

    private void generateBoundaryBodyTests(ApiEndpoint endpoint,
                                           Map<String, Object> pathParams,
                                           Map<String, Object> queryParams,
                                           Map<String, String> headers,
                                           Map<String, String> cookies,
                                           ApiSchema bodySchema,
                                           List<ApiTestCase> result,
                                           Set<String> dedup) {
        if (!bodySchema.isObject()) return;
        Map<String, ApiSchema> props = bodySchema.getProperties();
        if (props == null || props.isEmpty()) return;

        Map<String, Object> validBase = (Map<String, Object>) validGen.generateValidValue(bodySchema, 0, GenerationStrategy.SCHEMA_VALID_FULL);

        for (Map.Entry<String, ApiSchema> entry : props.entrySet()) {
            if (result.size() >= config.getMaxTestCasesPerEndpoint()) break;
            String propName = entry.getKey();
            ApiSchema propSchema = entry.getValue();

            // String boundaries
            if (propSchema.isString()) {
                if (propSchema.getMinLength() != null) {
                    Map<String, Object> mutated = new LinkedHashMap<>(validBase);
                    mutated.put(propName, boundaryGen.generateMinLengthString(propSchema));

                    addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                            endpoint, TestCategory.BOUNDARY, GenerationStrategy.STRING_MIN_LENGTH_BOUNDARY,
                            pathParams, queryParams, headers, cookies, mutated, "application/json",
                            config.getSeed(), "String minLength boundary for property: " + propName,
                            propName, "minLength: " + propSchema.getMinLength(), null
                    ));
                }
                if (propSchema.getMaxLength() != null) {
                    Map<String, Object> mutated = new LinkedHashMap<>(validBase);
                    mutated.put(propName, boundaryGen.generateMaxLengthString(propSchema));

                    addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                            endpoint, TestCategory.BOUNDARY, GenerationStrategy.STRING_MAX_LENGTH_BOUNDARY,
                            pathParams, queryParams, headers, cookies, mutated, "application/json",
                            config.getSeed(), "String maxLength boundary for property: " + propName,
                            propName, "maxLength: " + propSchema.getMaxLength(), null
                    ));
                }
            }

            // Numeric boundaries
            if (propSchema.isNumber()) {
                if (propSchema.getMinimum() != null) {
                    Map<String, Object> mutated = new LinkedHashMap<>(validBase);
                    mutated.put(propName, boundaryGen.generateNumericMinBoundary(propSchema));

                    addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                            endpoint, TestCategory.BOUNDARY, GenerationStrategy.NUMERIC_MIN_BOUNDARY,
                            pathParams, queryParams, headers, cookies, mutated, "application/json",
                            config.getSeed(), "Numeric minimum boundary for property: " + propName,
                            propName, "minimum: " + propSchema.getMinimum(), null
                    ));
                }
                if (propSchema.getMaximum() != null) {
                    Map<String, Object> mutated = new LinkedHashMap<>(validBase);
                    mutated.put(propName, boundaryGen.generateNumericMaxBoundary(propSchema));

                    addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                            endpoint, TestCategory.BOUNDARY, GenerationStrategy.NUMERIC_MAX_BOUNDARY,
                            pathParams, queryParams, headers, cookies, mutated, "application/json",
                            config.getSeed(), "Numeric maximum boundary for property: " + propName,
                            propName, "maximum: " + propSchema.getMaximum(), null
                    ));
                }
            }

            // Array boundaries
            if (propSchema.isArray()) {
                // Empty array
                Map<String, Object> emptyArrMutated = new LinkedHashMap<>(validBase);
                emptyArrMutated.put(propName, List.of());
                addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                        endpoint, TestCategory.BOUNDARY, GenerationStrategy.ARRAY_EMPTY_BOUNDARY,
                        pathParams, queryParams, headers, cookies, emptyArrMutated, "application/json",
                        config.getSeed(), "Empty array boundary for property: " + propName,
                        propName, "empty array", null
                ));

                if (propSchema.getMinItems() != null) {
                    Map<String, Object> mutated = new LinkedHashMap<>(validBase);
                    mutated.put(propName, boundaryGen.generateMinItemsArray(propSchema));
                    addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                            endpoint, TestCategory.BOUNDARY, GenerationStrategy.ARRAY_MIN_ITEMS_BOUNDARY,
                            pathParams, queryParams, headers, cookies, mutated, "application/json",
                            config.getSeed(), "Array minItems boundary for property: " + propName,
                            propName, "minItems: " + propSchema.getMinItems(), null
                    ));
                }

                if (propSchema.getMaxItems() != null) {
                    Map<String, Object> mutated = new LinkedHashMap<>(validBase);
                    mutated.put(propName, boundaryGen.generateMaxItemsArray(propSchema));
                    addTestCaseIfUnique(result, dedup, testCaseFactory.createTestCase(
                            endpoint, TestCategory.BOUNDARY, GenerationStrategy.ARRAY_MAX_ITEMS_BOUNDARY,
                            pathParams, queryParams, headers, cookies, mutated, "application/json",
                            config.getSeed(), "Array maxItems boundary for property: " + propName,
                            propName, "maxItems: " + propSchema.getMaxItems(), null
                    ));
                }
            }
        }
    }

    private void addTestCaseIfUnique(List<ApiTestCase> sink, Set<String> dedup, ApiTestCase tc) {
        if (sink.size() >= config.getMaxTestCasesPerEndpoint()) {
            return;
        }
        String sig = tc.category() + "|" + tc.strategy() + "|" + tc.targetedProperty() + "|"
                + Objects.hashCode(tc.pathParameters()) + "|" + Objects.hashCode(tc.queryParameters())
                + "|" + Objects.hashCode(tc.requestBody());

        if (dedup.add(sig)) {
            sink.add(tc);
        }
    }

    private Map<String, Object> buildBaselinePathParams(ApiEndpoint endpoint) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (ApiParameter p : endpoint.getPathParameters()) {
            map.put(p.getName(), validGen.generateParameterValue(p));
        }
        return map;
    }

    private Map<String, Object> buildBaselineQueryParams(ApiEndpoint endpoint, boolean includeOptional) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (ApiParameter p : endpoint.getQueryParameters()) {
            if (p.isRequired() || includeOptional) {
                map.put(p.getName(), validGen.generateParameterValue(p));
            }
        }
        return map;
    }

    private Map<String, String> buildBaselineHeaders(ApiEndpoint endpoint) {
        Map<String, String> map = new LinkedHashMap<>();
        for (ApiParameter p : endpoint.getHeaderParameters()) {
            if (p.isRequired()) {
                map.put(p.getName(), String.valueOf(validGen.generateParameterValue(p)));
            }
        }
        return map;
    }

    private Map<String, String> buildBaselineCookies(ApiEndpoint endpoint) {
        Map<String, String> map = new LinkedHashMap<>();
        for (ApiParameter p : endpoint.getCookieParameters()) {
            if (p.isRequired()) {
                map.put(p.getName(), String.valueOf(validGen.generateParameterValue(p)));
            }
        }
        return map;
    }

    private boolean hasOptionalElements(ApiEndpoint endpoint, ApiSchema bodySchema) {
        boolean hasOptionalQuery = endpoint.getQueryParameters().stream().anyMatch(p -> !p.isRequired());
        if (hasOptionalQuery) return true;
        if (bodySchema != null && bodySchema.isObject()) {
            int totalProps = bodySchema.getProperties().size();
            int requiredProps = bodySchema.getRequiredProperties().size();
            return totalProps > requiredProps;
        }
        return false;
    }

    public GenerationConfig getConfig() {
        return config;
    }

    public ValidInputGenerator getValidInputGenerator() {
        return validGen;
    }

    public InvalidInputGenerator getInvalidInputGenerator() {
        return invalidGen;
    }

    public BoundaryValueGenerator getBoundaryValueGenerator() {
        return boundaryGen;
    }
}

