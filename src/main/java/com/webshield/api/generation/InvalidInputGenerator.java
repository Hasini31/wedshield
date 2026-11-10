package com.webshield.api.generation;

import com.webshield.api.models.ApiParameter;
import com.webshield.api.models.ApiSchema;
import com.webshield.api.models.SchemaType;

import java.math.BigDecimal;
import java.util.*;

/**
 * Generates systematic negative / invalid inputs targeting schema constraints,
 * type mismatches, missing required fields, and boundary violations.
 */
public class InvalidInputGenerator {

    private final ValidInputGenerator validGen;
    private final GenerationConfig config;
    private final Random random;

    public InvalidInputGenerator(ValidInputGenerator validGen, GenerationConfig config, Random random) {
        this.validGen = validGen;
        this.config = config != null ? config : GenerationConfig.defaultConfig();
        this.random = random != null ? random : new Random(this.config.getSeed());
    }

    /**
     * Generates a type mismatch value incompatible with the schema type.
     */
    public Object generateTypeMismatch(ApiSchema schema) {
        SchemaType type = schema != null ? schema.getType() : SchemaType.STRING;
        return switch (type) {
            case STRING -> 999999;
            case INTEGER -> "invalid_string_where_integer_expected";
            case NUMBER -> "not_a_valid_number";
            case BOOLEAN -> "neither_true_nor_false";
            case OBJECT -> "string_instead_of_object";
            case ARRAY -> Map.of("error", "object_instead_of_array");
            case ANY -> 12345;
        };
    }

    /**
     * Generates an invalid format representation (e.g. malformed email or UUID).
     */
    public String generateInvalidFormat(ApiSchema schema) {
        String format = schema.getFormat() != null ? schema.getFormat().toLowerCase(Locale.ROOT) : "";
        return switch (format) {
            case "email" -> "plainaddress-without-at-sign";
            case "uuid" -> "1234-not-a-valid-uuid";
            case "date-time" -> "2026-13-45T99:99:99Z";
            case "date" -> "2026-99-99";
            case "uri", "url" -> "ht!tp://invalid uri with spaces";
            case "ipv4" -> "999.999.999.999";
            case "ipv6" -> "2001:::invalid::ipv6";
            default -> "invalid_format_data";
        };
    }

    /**
     * Generates an unlisted, invalid enum value.
     */
    public String generateInvalidEnum(ApiSchema schema) {
        return "UNKNOWN_ILLEGAL_ENUM_" + (Math.abs(random.nextInt()) % 9000 + 1000);
    }

    /**
     * Generates a string exceeding the declared maxLength constraint.
     */
    public String generateStringLengthExceeded(ApiSchema schema) {
        int max = schema.getMaxLength() != null ? schema.getMaxLength() : 255;
        int overflowLength = max + 10;
        return "X".repeat(overflowLength);
    }

    /**
     * Generates a string strictly below the declared minLength constraint.
     */
    public String generateStringLengthBelowMin(ApiSchema schema) {
        int min = schema.getMinLength() != null ? schema.getMinLength() : 1;
        if (min <= 1) {
            return "";
        }
        return "a".repeat(min - 1);
    }

    /**
     * Generates a numeric value strictly below the minimum allowed bound.
     */
    public Number generateNumericBelowMin(ApiSchema schema) {
        if (schema.getMinimum() != null) {
            if (schema.isInteger()) {
                long minVal = schema.getMinimum().longValue();
                return schema.isExclusiveMinimum() ? minVal : (minVal - 1);
            } else {
                BigDecimal minVal = schema.getMinimum();
                return schema.isExclusiveMinimum() ? minVal : minVal.subtract(BigDecimal.ONE);
            }
        }
        return -999999;
    }

    /**
     * Generates a numeric value strictly above the maximum allowed bound.
     */
    public Number generateNumericAboveMax(ApiSchema schema) {
        if (schema.getMaximum() != null) {
            if (schema.isInteger()) {
                long maxVal = schema.getMaximum().longValue();
                return schema.isExclusiveMaximum() ? maxVal : (maxVal + 1);
            } else {
                BigDecimal maxVal = schema.getMaximum();
                return schema.isExclusiveMaximum() ? maxVal : maxVal.add(BigDecimal.ONE);
            }
        }
        return 999999999L;
    }

    /**
     * Generates array item count exceeding the maxItems constraint.
     */
    public List<Object> generateArrayOverflow(ApiSchema schema) {
        int max = schema.getMaxItems() != null ? schema.getMaxItems() : 10;
        int overflowCount = max + 2;
        List<Object> list = new ArrayList<>();
        ApiSchema itemsSchema = schema.getItems() != null ? schema.getItems() : ApiSchema.ofType(SchemaType.STRING);
        for (int i = 0; i < overflowCount; i++) {
            list.add(validGen.generateValidValue(itemsSchema, 0, GenerationStrategy.SCHEMA_VALID_FULL));
        }
        return list;
    }
}

