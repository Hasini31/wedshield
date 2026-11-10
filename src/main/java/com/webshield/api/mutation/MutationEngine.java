package com.webshield.api.mutation;

import com.webshield.api.generation.ApiTestCase;
import com.webshield.api.generation.GenerationStrategy;
import com.webshield.api.generation.TestCategory;
import com.webshield.api.models.ApiEndpoint;
import com.webshield.api.models.ApiParameter;
import com.webshield.api.models.ApiSchema;
import com.webshield.api.models.ParsedApiSpecification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Schema-aware API Input Mutation Engine.
 * Systematically mutates valid or boundary test cases to produce high-value negative,
 * edge-case, and security assessment test variations.
 */
@Service
public class MutationEngine {

    private static final Logger log = LoggerFactory.getLogger(MutationEngine.class);
    private static final Pattern GEN_PATTERN = Pattern.compile("-GEN(\\d+)-");

    private final MutationConfig defaultConfig;
    private final AtomicLong counter = new AtomicLong(1);

    public MutationEngine() {
        this(MutationConfig.defaultConfig());
    }

    public MutationEngine(MutationConfig defaultConfig) {
        this.defaultConfig = defaultConfig != null ? defaultConfig : MutationConfig.defaultConfig();
    }

    /**
     * Mutates an entire test suite against a parsed OpenAPI specification.
     */
    public List<MutationResult> mutateSuite(List<ApiTestCase> parentSuite, ParsedApiSpecification spec) {
        return mutateSuite(parentSuite, spec, defaultConfig);
    }

    /**
     * Mutates an entire test suite against a specification using a custom configuration.
     */
    public List<MutationResult> mutateSuite(List<ApiTestCase> parentSuite, ParsedApiSpecification spec, MutationConfig config) {
        if (parentSuite == null || parentSuite.isEmpty()) {
            return List.of();
        }
        MutationConfig activeConfig = config != null ? config : defaultConfig;
        List<MutationResult> results = new ArrayList<>();
        Set<String> suiteDedup = new HashSet<>();

        for (ApiTestCase parent : parentSuite) {
            if (results.size() >= activeConfig.getMaxTotalMutations()) {
                log.info("Reached maximum total mutations limit: {}", activeConfig.getMaxTotalMutations());
                break;
            }

            ApiEndpoint endpoint = spec != null ? spec.findEndpoint(parent.path(), parent.method()).orElse(null) : null;
            List<MutationResult> mutations = mutateTestCase(parent, endpoint, activeConfig);

            for (MutationResult res : mutations) {
                if (results.size() >= activeConfig.getMaxTotalMutations()) {
                    break;
                }
                String sig = buildCanonicalSignature(res);
                if (suiteDedup.add(sig)) {
                    results.add(res);
                }
            }
        }

        return Collections.unmodifiableList(results);
    }

    /**
     * Mutates a single test case using the default configuration.
     */
    public List<MutationResult> mutateTestCase(ApiTestCase parentTestCase, ApiEndpoint endpoint) {
        return mutateTestCase(parentTestCase, endpoint, defaultConfig);
    }

    /**
     * Mutates a single test case using a specific configuration.
     */
    public List<MutationResult> mutateTestCase(ApiTestCase parentTestCase, ApiEndpoint endpoint, MutationConfig config) {
        if (parentTestCase == null) {
            return List.of();
        }
        MutationConfig activeConfig = config != null ? config : defaultConfig;

        // Check depth limit
        int parentGen = extractGeneration(parentTestCase);
        if (parentGen >= activeConfig.getMaxMutationDepth()) {
            log.debug("Test case {} has reached max mutation depth {}", parentTestCase.id(), parentGen);
            return List.of();
        }
        int childGen = parentGen + 1;

        Random random = new Random(activeConfig.getSeed());
        List<MutationResult> candidates = new ArrayList<>();
        Set<String> localDedup = new HashSet<>();

        // 1. Mutate request body if present
        if (parentTestCase.hasRequestBody() && parentTestCase.requestBody() instanceof Map<?, ?> bodyMap) {
            @SuppressWarnings("unchecked")
            Map<String, Object> typedMap = (Map<String, Object>) bodyMap;
            ApiSchema rootSchema = (endpoint != null && endpoint.hasRequestBody())
                    ? endpoint.getRequestBody().getJsonSchema()
                    : null;

            // Property-level mutations
            for (Map.Entry<String, Object> entry : typedMap.entrySet()) {
                String propName = entry.getKey();
                Object originalVal = entry.getValue();
                ApiSchema propSchema = rootSchema != null ? rootSchema.getProperty(propName) : null;

                List<MutationOperatorType> applicable = selectApplicableOperators(originalVal, propSchema, activeConfig);
                for (MutationOperatorType op : applicable) {
                    if (candidates.size() >= activeConfig.getMaxMutationsPerTestCase()) break;
                    if (random.nextDouble() > activeConfig.getMutationProbability()) continue;

                    Object mutatedVal = applyOperator(op, originalVal, propSchema, random);
                    Map<String, Object> mutatedBody = (Map<String, Object>) StructureMutation.deepCopy(typedMap);
                    mutatedBody.put(propName, mutatedVal);

                    addResultIfUnique(candidates, localDedup, activeConfig, parentTestCase, op,
                            "body." + propName, originalVal, mutatedVal, childGen, activeConfig.getSeed(),
                            parentTestCase.pathParameters(), parentTestCase.queryParameters(),
                            parentTestCase.headers(), parentTestCase.cookies(), mutatedBody);
                }
            }

            // Structural object mutations
            if (activeConfig.isCategoryEnabled(MutationCategory.STRUCTURE)) {
                List<MutationOperatorType> structOps = List.of(
                        MutationOperatorType.STRUCTURE_REMOVE_OPTIONAL,
                        MutationOperatorType.STRUCTURE_REMOVE_REQUIRED,
                        MutationOperatorType.STRUCTURE_ADD_UNEXPECTED,
                        MutationOperatorType.STRUCTURE_OBJECT_TO_PRIMITIVE,
                        MutationOperatorType.STRUCTURE_WRAP_IN_ARRAY,
                        MutationOperatorType.STRUCTURE_DUPLICATE_NESTED,
                        MutationOperatorType.STRUCTURE_CHANGE_NESTED_TYPE
                );

                for (MutationOperatorType op : structOps) {
                    if (candidates.size() >= activeConfig.getMaxMutationsPerTestCase()) break;
                    if (random.nextDouble() > activeConfig.getMutationProbability()) continue;

                    Object mutatedBody = applyStructureOperator(op, typedMap, rootSchema, random);
                    addResultIfUnique(candidates, localDedup, activeConfig, parentTestCase, op,
                            "body#structure", typedMap, mutatedBody, childGen, activeConfig.getSeed(),
                            parentTestCase.pathParameters(), parentTestCase.queryParameters(),
                            parentTestCase.headers(), parentTestCase.cookies(), mutatedBody);
                }
            }
        } else if (parentTestCase.hasRequestBody() && parentTestCase.requestBody() instanceof List<?> bodyList) {
            // Array body mutations
            if (activeConfig.isCategoryEnabled(MutationCategory.STRUCTURE)) {
                @SuppressWarnings("unchecked")
                List<Object> typedList = (List<Object>) bodyList;
                List<MutationOperatorType> arrayOps = List.of(
                        MutationOperatorType.STRUCTURE_CHANGE_ARRAY_LENGTH,
                        MutationOperatorType.STRUCTURE_UNWRAP_ARRAY,
                        MutationOperatorType.STRUCTURE_OBJECT_TO_PRIMITIVE
                );
                for (MutationOperatorType op : arrayOps) {
                    if (candidates.size() >= activeConfig.getMaxMutationsPerTestCase()) break;
                    Object mutatedBody = applyStructureOperator(op, typedList, null, random);
                    addResultIfUnique(candidates, localDedup, activeConfig, parentTestCase, op,
                            "body#array", typedList, mutatedBody, childGen, activeConfig.getSeed(),
                            parentTestCase.pathParameters(), parentTestCase.queryParameters(),
                            parentTestCase.headers(), parentTestCase.cookies(), mutatedBody);
                }
            }
        }

        // 2. Mutate query parameters
        if (!parentTestCase.queryParameters().isEmpty()) {
            for (Map.Entry<String, Object> entry : parentTestCase.queryParameters().entrySet()) {
                String paramName = entry.getKey();
                Object originalVal = entry.getValue();
                ApiSchema paramSchema = endpoint != null
                        ? endpoint.getParameter(paramName, com.webshield.api.models.ParameterLocation.QUERY).map(ApiParameter::getSchema).orElse(null)
                        : null;

                List<MutationOperatorType> ops = selectApplicableOperators(originalVal, paramSchema, activeConfig);
                for (MutationOperatorType op : ops) {
                    if (candidates.size() >= activeConfig.getMaxMutationsPerTestCase()) break;
                    if (random.nextDouble() > activeConfig.getMutationProbability()) continue;

                    Object mutatedVal = applyOperator(op, originalVal, paramSchema, random);
                    Map<String, Object> mutatedParams = (Map<String, Object>) StructureMutation.deepCopy(parentTestCase.queryParameters());
                    mutatedParams.put(paramName, mutatedVal);

                    addResultIfUnique(candidates, localDedup, activeConfig, parentTestCase, op,
                            "query." + paramName, originalVal, mutatedVal, childGen, activeConfig.getSeed(),
                            parentTestCase.pathParameters(), mutatedParams,
                            parentTestCase.headers(), parentTestCase.cookies(), parentTestCase.requestBody());
                }
            }
        }

        // 3. Mutate path parameters
        if (!parentTestCase.pathParameters().isEmpty()) {
            for (Map.Entry<String, Object> entry : parentTestCase.pathParameters().entrySet()) {
                String paramName = entry.getKey();
                Object originalVal = entry.getValue();
                ApiSchema paramSchema = endpoint != null
                        ? endpoint.getParameter(paramName, com.webshield.api.models.ParameterLocation.PATH).map(ApiParameter::getSchema).orElse(null)
                        : null;

                List<MutationOperatorType> ops = selectApplicableOperators(originalVal, paramSchema, activeConfig);
                for (MutationOperatorType op : ops) {
                    if (candidates.size() >= activeConfig.getMaxMutationsPerTestCase()) break;
                    if (random.nextDouble() > activeConfig.getMutationProbability()) continue;

                    Object mutatedVal = applyOperator(op, originalVal, paramSchema, random);
                    Map<String, Object> mutatedParams = (Map<String, Object>) StructureMutation.deepCopy(parentTestCase.pathParameters());
                    mutatedParams.put(paramName, mutatedVal);

                    addResultIfUnique(candidates, localDedup, activeConfig, parentTestCase, op,
                            "path." + paramName, originalVal, mutatedVal, childGen, activeConfig.getSeed(),
                            mutatedParams, parentTestCase.queryParameters(),
                            parentTestCase.headers(), parentTestCase.cookies(), parentTestCase.requestBody());
                }
            }
        }

        return Collections.unmodifiableList(candidates);
    }

    /**
     * Mutates a single targeted field or structure with a specific operator deterministically.
     */
    public MutationResult mutateField(ApiTestCase parentTestCase, ApiEndpoint endpoint,
                                      String targetField, MutationOperatorType operatorType, Long seed) {
        if (parentTestCase == null || operatorType == null) {
            throw new IllegalArgumentException("parentTestCase and operatorType must not be null");
        }
        long activeSeed = seed != null ? seed : defaultConfig.getSeed();
        Random random = new Random(activeSeed);
        int childGen = extractGeneration(parentTestCase) + 1;

        Map<String, Object> pathParams = (Map<String, Object>) StructureMutation.deepCopy(parentTestCase.pathParameters());
        Map<String, Object> queryParams = (Map<String, Object>) StructureMutation.deepCopy(parentTestCase.queryParameters());
        Map<String, String> headers = (Map<String, String>) StructureMutation.deepCopy(parentTestCase.headers());
        Map<String, String> cookies = (Map<String, String>) StructureMutation.deepCopy(parentTestCase.cookies());
        Object requestBody = StructureMutation.deepCopy(parentTestCase.requestBody());

        Object originalVal = null;
        Object mutatedVal = null;

        if (targetField != null && targetField.startsWith("body.")) {
            String propName = targetField.substring("body.".length());
            ApiSchema rootSchema = (endpoint != null && endpoint.hasRequestBody())
                    ? endpoint.getRequestBody().getJsonSchema()
                    : null;
            ApiSchema propSchema = rootSchema != null ? rootSchema.getProperty(propName) : null;

            if (requestBody instanceof Map<?, ?> bodyMap) {
                @SuppressWarnings("unchecked")
                Map<String, Object> mutableMap = (Map<String, Object>) bodyMap;
                originalVal = mutableMap.get(propName);
                mutatedVal = applyOperator(operatorType, originalVal, propSchema, random);
                mutableMap.put(propName, mutatedVal);
            }
        } else if (targetField != null && targetField.equals("body#structure")) {
            ApiSchema rootSchema = (endpoint != null && endpoint.hasRequestBody())
                    ? endpoint.getRequestBody().getJsonSchema()
                    : null;
            originalVal = requestBody;
            mutatedVal = applyStructureOperator(operatorType, requestBody, rootSchema, random);
            requestBody = mutatedVal;
        } else if (targetField != null && targetField.startsWith("query.")) {
            String paramName = targetField.substring("query.".length());
            originalVal = queryParams.get(paramName);
            ApiSchema paramSchema = endpoint != null
                    ? endpoint.getParameter(paramName, com.webshield.api.models.ParameterLocation.QUERY).map(ApiParameter::getSchema).orElse(null)
                    : null;
            mutatedVal = applyOperator(operatorType, originalVal, paramSchema, random);
            queryParams.put(paramName, mutatedVal);
        } else if (targetField != null && targetField.startsWith("path.")) {
            String paramName = targetField.substring("path.".length());
            originalVal = pathParams.get(paramName);
            ApiSchema paramSchema = endpoint != null
                    ? endpoint.getParameter(paramName, com.webshield.api.models.ParameterLocation.PATH).map(ApiParameter::getSchema).orElse(null)
                    : null;
            mutatedVal = applyOperator(operatorType, originalVal, paramSchema, random);
            pathParams.put(paramName, mutatedVal);
        } else {
            // General structure mutation fallback on body
            originalVal = requestBody;
            mutatedVal = applyStructureOperator(operatorType, requestBody, null, random);
            requestBody = mutatedVal;
        }

        String newId = generateMutatedId(parentTestCase.id(), childGen);
        String desc = "Mutated [" + targetField + "] via operator " + operatorType.name();

        MutationContext context = new MutationContext(
                parentTestCase.id(), operatorType, targetField,
                originalVal, mutatedVal, childGen, activeSeed, desc
        );

        ApiTestCase childTestCase = new ApiTestCase(
                newId,
                parentTestCase.endpointIdentifier(),
                parentTestCase.method(),
                parentTestCase.path(),
                TestCategory.MUTATION,
                pathParams, queryParams, headers, cookies,
                requestBody,
                parentTestCase.contentType(),
                GenerationStrategy.MUTATION_INPUT,
                activeSeed,
                desc,
                targetField,
                operatorType.name(),
                parentTestCase.id()
        );

        return new MutationResult(childTestCase, context);
    }

    /**
     * Determines applicable mutation operators for a target value and schema.
     */
    public List<MutationOperatorType> selectApplicableOperators(Object value, ApiSchema schema, MutationConfig config) {
        List<MutationOperatorType> list = new ArrayList<>();

        boolean isEnum = (schema != null && !schema.getEnumValues().isEmpty());
        boolean isNumeric = (schema != null && schema.isNumber()) || (value instanceof Number);
        boolean isBoolean = (schema != null && schema.isBoolean()) || (value instanceof Boolean);
        boolean isString = (schema != null && schema.isString()) || (value instanceof String);

        if (isEnum && config.isCategoryEnabled(MutationCategory.ENUM)) {
            list.add(MutationOperatorType.ENUM_REPLACE_VALID);
            list.add(MutationOperatorType.ENUM_INJECT_INVALID);
            list.add(MutationOperatorType.ENUM_CASE_VARIATION);
            list.add(MutationOperatorType.ENUM_EMPTY);
            list.add(MutationOperatorType.ENUM_NULL);
        } else if (isNumeric && config.isCategoryEnabled(MutationCategory.NUMERIC)) {
            list.add(MutationOperatorType.NUMERIC_INCREMENT);
            list.add(MutationOperatorType.NUMERIC_DECREMENT);
            list.add(MutationOperatorType.NUMERIC_SIGN_REVERSAL);
            list.add(MutationOperatorType.NUMERIC_ZERO);
            list.add(MutationOperatorType.NUMERIC_NEGATIVE);
            list.add(MutationOperatorType.NUMERIC_BOUNDARY_MIN_MAX);
            list.add(MutationOperatorType.NUMERIC_OUTSIDE_BOUNDS);
            list.add(MutationOperatorType.NUMERIC_OVERFLOW);
            list.add(MutationOperatorType.NUMERIC_LARGE_VALUE);
            list.add(MutationOperatorType.NUMERIC_FLOATING_POINT_EDGE);
        } else if (isBoolean && config.isCategoryEnabled(MutationCategory.BOOLEAN)) {
            list.add(MutationOperatorType.BOOLEAN_INVERT);
            list.add(MutationOperatorType.BOOLEAN_NULL_INJECT);
            list.add(MutationOperatorType.BOOLEAN_REMOVE_OPTIONAL);
        } else if (isString && config.isCategoryEnabled(MutationCategory.STRING)) {
            list.add(MutationOperatorType.STRING_INSERTION);
            list.add(MutationOperatorType.STRING_DELETION);
            list.add(MutationOperatorType.STRING_REPLACEMENT);
            list.add(MutationOperatorType.STRING_EMPTY);
            list.add(MutationOperatorType.STRING_WHITESPACE);
            list.add(MutationOperatorType.STRING_EXPANSION);
            list.add(MutationOperatorType.STRING_TRUNCATION);
            list.add(MutationOperatorType.STRING_SPECIAL_CHARS);
            list.add(MutationOperatorType.STRING_QUOTES_DELIMITERS);
            list.add(MutationOperatorType.STRING_UNICODE);
            list.add(MutationOperatorType.STRING_CONTROL_CHARS);
        }

        return list;
    }

    /**
     * Applies value-level mutation operators.
     */
    public Object applyOperator(MutationOperatorType type, Object value, ApiSchema schema, Random random) {
        if (type.getCategory() == MutationCategory.STRING) {
            String str = value != null ? String.valueOf(value) : "test";
            return StringMutation.apply(type, str, schema, random);
        }
        if (type.getCategory() == MutationCategory.NUMERIC) {
            Number num = value instanceof Number n ? n : 10;
            return NumericMutation.apply(type, num, schema, random);
        }
        if (type.getCategory() == MutationCategory.BOOLEAN) {
            Boolean b = value instanceof Boolean bool ? bool : Boolean.TRUE;
            return BooleanMutation.apply(type, b, schema);
        }
        if (type.getCategory() == MutationCategory.ENUM) {
            String str = value != null ? String.valueOf(value) : "";
            return EnumMutation.apply(type, str, schema, random);
        }
        return value;
    }

    /**
     * Applies structural JSON mutation operators.
     */
    @SuppressWarnings("unchecked")
    public Object applyStructureOperator(MutationOperatorType type, Object target, ApiSchema schema, Random random) {
        if (target instanceof Map<?, ?> map) {
            Map<String, Object> typedMap = (Map<String, Object>) map;
            return switch (type) {
                case STRUCTURE_REMOVE_OPTIONAL -> StructureMutation.removeOptionalProperty(typedMap, schema, random);
                case STRUCTURE_REMOVE_REQUIRED -> StructureMutation.removeRequiredProperty(typedMap, schema, random);
                case STRUCTURE_ADD_UNEXPECTED -> StructureMutation.addUnexpectedProperty(typedMap, random);
                case STRUCTURE_OBJECT_TO_PRIMITIVE -> StructureMutation.replaceObjectWithPrimitive(typedMap);
                case STRUCTURE_WRAP_IN_ARRAY -> StructureMutation.wrapInArray(typedMap);
                case STRUCTURE_DUPLICATE_NESTED -> StructureMutation.duplicateNestedStructure(typedMap, random);
                case STRUCTURE_CHANGE_NESTED_TYPE -> StructureMutation.changeNestedObjectType(typedMap, random);
                default -> StructureMutation.deepCopy(typedMap);
            };
        } else if (target instanceof List<?> list) {
            List<Object> typedList = (List<Object>) list;
            return switch (type) {
                case STRUCTURE_CHANGE_ARRAY_LENGTH -> StructureMutation.changeArrayLength(typedList, random);
                case STRUCTURE_UNWRAP_ARRAY -> StructureMutation.unwrapArray(typedList);
                case STRUCTURE_OBJECT_TO_PRIMITIVE -> StructureMutation.replaceObjectWithPrimitive(typedList);
                case STRUCTURE_WRAP_IN_ARRAY -> StructureMutation.wrapInArray(typedList);
                default -> StructureMutation.deepCopy(typedList);
            };
        } else {
            // Primitive target
            return switch (type) {
                case STRUCTURE_PRIMITIVE_TO_OBJECT -> StructureMutation.replacePrimitiveWithObject(target);
                case STRUCTURE_WRAP_IN_ARRAY -> StructureMutation.wrapInArray(target);
                default -> target;
            };
        }
    }

    private void addResultIfUnique(List<MutationResult> sink, Set<String> dedup, MutationConfig config,
                                   ApiTestCase parent, MutationOperatorType op, String targetField,
                                   Object originalVal, Object mutatedVal, int generation, long seed,
                                   Map<String, Object> pathParams, Map<String, Object> queryParams,
                                   Map<String, String> headers, Map<String, String> cookies, Object body) {
        if (sink.size() >= config.getMaxMutationsPerTestCase()) {
            return;
        }

        String sig = op.name() + "|" + targetField + "|"
                + Objects.hashCode(pathParams) + "|" + Objects.hashCode(queryParams) + "|"
                + Objects.hashCode(headers) + "|" + Objects.hashCode(body);

        if (dedup.add(sig)) {
            String newId = generateMutatedId(parent.id(), generation);
            String desc = "Mutated [" + targetField + "] via operator " + op.name();

            MutationContext context = new MutationContext(
                    parent.id(), op, targetField, originalVal, mutatedVal, generation, seed, desc
            );

            ApiTestCase childTestCase = new ApiTestCase(
                    newId,
                    parent.endpointIdentifier(),
                    parent.method(),
                    parent.path(),
                    TestCategory.MUTATION,
                    pathParams, queryParams, headers, cookies,
                    body,
                    parent.contentType(),
                    GenerationStrategy.MUTATION_INPUT,
                    seed,
                    desc,
                    targetField,
                    op.name(),
                    parent.id()
            );

            sink.add(new MutationResult(childTestCase, context));
        }
    }

    private String buildCanonicalSignature(MutationResult res) {
        ApiTestCase tc = res.testCase();
        return res.context().operatorType() + "|" + res.context().targetedField() + "|"
                + Objects.hashCode(tc.pathParameters()) + "|" + Objects.hashCode(tc.queryParameters()) + "|"
                + Objects.hashCode(tc.headers()) + "|" + Objects.hashCode(tc.requestBody());
    }

    private String generateMutatedId(String parentId, int generation) {
        return "MUT-" + (parentId != null ? parentId : "TC") + "-GEN" + generation + "-" + counter.getAndIncrement();
    }

    private int extractGeneration(ApiTestCase tc) {
        if (tc == null || tc.parentTestCaseId() == null || tc.parentTestCaseId().isBlank()) {
            return 0;
        }
        if (tc.id() != null) {
            Matcher matcher = GEN_PATTERN.matcher(tc.id());
            int gen = 0;
            while (matcher.find()) {
                try {
                    gen = Integer.parseInt(matcher.group(1));
                } catch (NumberFormatException ignored) {
                }
            }
            if (gen > 0) {
                return gen;
            }
        }
        return 1;
    }

    public MutationConfig getDefaultConfig() {
        return defaultConfig;
    }
}
