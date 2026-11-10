package com.webshield.api.generation;

import com.webshield.api.models.ApiSchema;
import com.webshield.api.models.SchemaType;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

/**
 * Generates boundary-focused inputs exploring minimum, maximum, empty, and edge values.
 */
public class BoundaryValueGenerator {

    private final ValidInputGenerator validGen;
    private final GenerationConfig config;

    public BoundaryValueGenerator(ValidInputGenerator validGen, GenerationConfig config) {
        this.validGen = validGen;
        this.config = config != null ? config : GenerationConfig.defaultConfig();
    }

    /**
     * Generates a string with exact minimum length.
     */
    public String generateMinLengthString(ApiSchema schema) {
        int min = schema.getMinLength() != null ? schema.getMinLength() : 0;
        return "m".repeat(min);
    }

    /**
     * Generates a string with exact maximum length.
     */
    public String generateMaxLengthString(ApiSchema schema) {
        int max = schema.getMaxLength() != null ? schema.getMaxLength() : 255;
        return "M".repeat(max);
    }

    /**
     * Generates a string with length exceeding maximum by exactly 1 character.
     */
    public String generateMaxLengthPlusOneString(ApiSchema schema) {
        int max = schema.getMaxLength() != null ? schema.getMaxLength() : 255;
        return "M".repeat(max + 1);
    }

    /**
     * Generates exact minimum numeric boundary (respecting exclusiveMinimum).
     */
    public Number generateNumericMinBoundary(ApiSchema schema) {
        if (schema.getMinimum() == null) {
            return schema.isInteger() ? 0L : BigDecimal.ZERO;
        }

        if (schema.isInteger()) {
            long min = schema.getMinimum().longValue();
            return schema.isExclusiveMinimum() ? (min + 1) : min;
        } else {
            BigDecimal min = schema.getMinimum();
            return schema.isExclusiveMinimum() ? min.add(BigDecimal.valueOf(0.01)) : min;
        }
    }

    /**
     * Generates exact maximum numeric boundary (respecting exclusiveMaximum).
     */
    public Number generateNumericMaxBoundary(ApiSchema schema) {
        if (schema.getMaximum() == null) {
            return schema.isInteger() ? 1000L : BigDecimal.valueOf(1000.0);
        }

        if (schema.isInteger()) {
            long max = schema.getMaximum().longValue();
            return schema.isExclusiveMaximum() ? (max - 1) : max;
        } else {
            BigDecimal max = schema.getMaximum();
            return schema.isExclusiveMaximum() ? max.subtract(BigDecimal.valueOf(0.01)) : max;
        }
    }

    /**
     * Generates an array with exact minimum items.
     */
    public List<Object> generateMinItemsArray(ApiSchema schema) {
        int min = schema.getMinItems() != null ? schema.getMinItems() : 0;
        List<Object> list = new ArrayList<>();
        ApiSchema itemsSchema = schema.getItems() != null ? schema.getItems() : ApiSchema.ofType(SchemaType.STRING);
        for (int i = 0; i < min; i++) {
            list.add(validGen.generateValidValue(itemsSchema, 0, GenerationStrategy.SCHEMA_VALID_FULL));
        }
        return list;
    }

    /**
     * Generates an array with exact maximum items.
     */
    public List<Object> generateMaxItemsArray(ApiSchema schema) {
        int max = schema.getMaxItems() != null ? schema.getMaxItems() : config.getMaxArrayElements();
        List<Object> list = new ArrayList<>();
        ApiSchema itemsSchema = schema.getItems() != null ? schema.getItems() : ApiSchema.ofType(SchemaType.STRING);
        for (int i = 0; i < max; i++) {
            list.add(validGen.generateValidValue(itemsSchema, 0, GenerationStrategy.SCHEMA_VALID_FULL));
        }
        return list;
    }
}

