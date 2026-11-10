package com.webshield.api.parser;

import com.webshield.api.models.ApiSchema;
import com.webshield.api.models.SchemaType;
import io.swagger.v3.oas.models.media.ArraySchema;
import io.swagger.v3.oas.models.media.ComposedSchema;
import io.swagger.v3.oas.models.media.Schema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.util.*;

/**
 * Extracts and maps OpenAPI Schema objects into WebShield's strongly-typed {@link ApiSchema} model,
 * resolving nested references, cycle detection, and constraint preservations.
 */
public class SchemaExtractor {

    private static final Logger log = LoggerFactory.getLogger(SchemaExtractor.class);

    private final SchemaResolver resolver;

    public SchemaExtractor(SchemaResolver resolver) {
        this.resolver = resolver;
    }

    /**
     * Converts a raw OpenAPI schema into an {@link ApiSchema} with recursion tracking.
     */
    public ApiSchema extractSchema(Schema<?> rawSchema) {
        return extractSchema(rawSchema, 0);
    }

    public ApiSchema extractSchema(Schema<?> rawSchema, int depth) {
        if (rawSchema == null) {
            return ApiSchema.ofType(SchemaType.ANY);
        }

        // Handle reference schemas
        String ref = rawSchema.get$ref();
        if (ref != null && !ref.isBlank()) {
            return extractReferencedSchema(rawSchema, ref, depth);
        }

        ApiSchema apiSchema = new ApiSchema();
        mapBasicMetadata(rawSchema, apiSchema);
        mapType(rawSchema, apiSchema);
        mapConstraints(rawSchema, apiSchema);

        if (depth >= SchemaResolver.MAX_RECURSION_DEPTH) {
            log.warn("Exceeded maximum recursion depth ({}) while parsing schema. Halting recursion.", depth);
            apiSchema.setDescription("Max recursion depth exceeded");
            return apiSchema;
        }

        // Handle Array items
        if (rawSchema instanceof ArraySchema arraySchema) {
            apiSchema.setType(SchemaType.ARRAY);
            if (arraySchema.getItems() != null) {
                apiSchema.setItems(extractSchema(arraySchema.getItems(), depth + 1));
            }
        } else if (rawSchema.getItems() != null) {
            apiSchema.setType(SchemaType.ARRAY);
            apiSchema.setItems(extractSchema(rawSchema.getItems(), depth + 1));
        }

        // Handle Object properties
        Map<String, Schema> rawProperties = rawSchema.getProperties();
        if (rawProperties != null && !rawProperties.isEmpty()) {
            if (apiSchema.getType() == SchemaType.ANY) {
                apiSchema.setType(SchemaType.OBJECT);
            }
            for (Map.Entry<String, Schema> entry : rawProperties.entrySet()) {
                String propName = entry.getKey();
                Schema<?> propSchema = entry.getValue();
                apiSchema.addProperty(propName, extractSchema(propSchema, depth + 1));
            }
        }

        // Required properties
        List<String> required = rawSchema.getRequired();
        if (required != null) {
            for (String req : required) {
                apiSchema.addRequiredProperty(req);
            }
        }

        // Additional properties
        Object addProps = rawSchema.getAdditionalProperties();
        if (addProps instanceof Boolean boolVal) {
            apiSchema.setAdditionalPropertiesAllowed(boolVal);
        } else if (addProps instanceof Schema<?> addSchema) {
            apiSchema.setAdditionalPropertiesAllowed(true);
            apiSchema.setAdditionalPropertiesSchema(extractSchema(addSchema, depth + 1));
        }

        // Composed Schemas (allOf, oneOf, anyOf)
        if (rawSchema instanceof ComposedSchema composedSchema) {
            mapComposedSchema(composedSchema, apiSchema, depth);
        } else {
            if (rawSchema.getAllOf() != null && !rawSchema.getAllOf().isEmpty()) {
                mapAllOf(rawSchema.getAllOf(), apiSchema, depth);
            }
            if (rawSchema.getOneOf() != null && !rawSchema.getOneOf().isEmpty()) {
                for (Schema<?> sub : rawSchema.getOneOf()) {
                    apiSchema.getOneOf().add(extractSchema(sub, depth + 1));
                }
            }
            if (rawSchema.getAnyOf() != null && !rawSchema.getAnyOf().isEmpty()) {
                for (Schema<?> sub : rawSchema.getAnyOf()) {
                    apiSchema.getAnyOf().add(extractSchema(sub, depth + 1));
                }
            }
        }

        return apiSchema;
    }

    private ApiSchema extractReferencedSchema(Schema<?> originSchema, String ref, int depth) {
        if (resolver == null) {
            ApiSchema unres = ApiSchema.ofType(SchemaType.OBJECT);
            unres.setRef(ref);
            return unres;
        }

        if (resolver.isCircular(ref) || depth >= SchemaResolver.MAX_RECURSION_DEPTH) {
            log.debug("Detected circular reference to: {}", ref);
            return ApiSchema.circular(ref, SchemaType.OBJECT);
        }

        Schema<?> targetSchema = resolver.resolveSchema(ref);
        if (targetSchema == null) {
            log.warn("Unresolvable local reference: {}", ref);
            ApiSchema missing = ApiSchema.ofType(SchemaType.OBJECT);
            missing.setRef(ref);
            missing.setDescription("Unresolved reference: " + ref);
            return missing;
        }

        resolver.pushRef(ref);
        try {
            ApiSchema resolved = extractSchema(targetSchema, depth + 1);
            resolved.setRef(ref);
            // If the referencing schema specified local overrides (e.g. description/nullable)
            if (originSchema.getDescription() != null) {
                resolved.setDescription(originSchema.getDescription());
            }
            if (originSchema.getNullable() != null) {
                resolved.setNullable(originSchema.getNullable());
            }
            return resolved;
        } finally {
            resolver.popRef(ref);
        }
    }

    private void mapBasicMetadata(Schema<?> rawSchema, ApiSchema apiSchema) {
        apiSchema.setTitle(rawSchema.getTitle());
        apiSchema.setDescription(rawSchema.getDescription());
        apiSchema.setFormat(rawSchema.getFormat());
        if (rawSchema.getNullable() != null) {
            apiSchema.setNullable(rawSchema.getNullable());
        }
        apiSchema.setDefaultValue(rawSchema.getDefault());
        apiSchema.setExample(rawSchema.getExample());
    }

    private void mapType(Schema<?> rawSchema, ApiSchema apiSchema) {
        String typeStr = rawSchema.getType();
        if (typeStr != null) {
            apiSchema.setType(SchemaType.fromString(typeStr));
        } else if (rawSchema instanceof ArraySchema || rawSchema.getItems() != null) {
            apiSchema.setType(SchemaType.ARRAY);
        } else if (rawSchema.getProperties() != null && !rawSchema.getProperties().isEmpty()) {
            apiSchema.setType(SchemaType.OBJECT);
        } else {
            apiSchema.setType(SchemaType.ANY);
        }
    }

    private void mapConstraints(Schema<?> rawSchema, ApiSchema apiSchema) {
        // String constraints
        apiSchema.setMinLength(rawSchema.getMinLength());
        apiSchema.setMaxLength(rawSchema.getMaxLength());
        apiSchema.setPattern(rawSchema.getPattern());

        // Numeric constraints
        apiSchema.setMinimum(rawSchema.getMinimum());
        apiSchema.setMaximum(rawSchema.getMaximum());
        if (rawSchema.getExclusiveMinimum() != null) {
            apiSchema.setExclusiveMinimum(rawSchema.getExclusiveMinimum());
        }
        if (rawSchema.getExclusiveMaximum() != null) {
            apiSchema.setExclusiveMaximum(rawSchema.getExclusiveMaximum());
        }

        // Array constraints
        apiSchema.setMinItems(rawSchema.getMinItems());
        apiSchema.setMaxItems(rawSchema.getMaxItems());
        if (rawSchema.getUniqueItems() != null) {
            apiSchema.setUniqueItems(rawSchema.getUniqueItems());
        }

        // Enums
        List<?> rawEnum = rawSchema.getEnum();
        if (rawEnum != null) {
            for (Object val : rawEnum) {
                if (val != null) {
                    apiSchema.addEnumValue(val.toString());
                }
            }
        }
    }

    private void mapComposedSchema(ComposedSchema composedSchema, ApiSchema apiSchema, int depth) {
        if (composedSchema.getAllOf() != null) {
            mapAllOf(composedSchema.getAllOf(), apiSchema, depth);
        }
        if (composedSchema.getOneOf() != null) {
            List<ApiSchema> oneOfList = new ArrayList<>();
            for (Schema<?> sub : composedSchema.getOneOf()) {
                oneOfList.add(extractSchema(sub, depth + 1));
            }
            apiSchema.setOneOf(oneOfList);
        }
        if (composedSchema.getAnyOf() != null) {
            List<ApiSchema> anyOfList = new ArrayList<>();
            for (Schema<?> sub : composedSchema.getAnyOf()) {
                anyOfList.add(extractSchema(sub, depth + 1));
            }
            apiSchema.setAnyOf(anyOfList);
        }
    }

    private void mapAllOf(List<Schema> allOfList, ApiSchema apiSchema, int depth) {
        List<ApiSchema> allOfResults = new ArrayList<>();
        for (Schema<?> sub : allOfList) {
            ApiSchema subSchema = extractSchema(sub, depth + 1);
            allOfResults.add(subSchema);

            // Merge subschema properties into target schema
            for (Map.Entry<String, ApiSchema> prop : subSchema.getProperties().entrySet()) {
                apiSchema.addProperty(prop.getKey(), prop.getValue());
            }
            for (String req : subSchema.getRequiredProperties()) {
                apiSchema.addRequiredProperty(req);
            }
            if (subSchema.getType() != SchemaType.ANY && apiSchema.getType() == SchemaType.ANY) {
                apiSchema.setType(subSchema.getType());
            }
        }
        apiSchema.setAllOf(allOfResults);
    }
}

