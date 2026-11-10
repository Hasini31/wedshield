package com.webshield.api.generation;

import com.webshield.api.models.ApiParameter;
import com.webshield.api.models.ApiSchema;
import com.webshield.api.models.SchemaType;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.*;

/**
 * Generates schema-compliant, structurally valid values for API parameters and request bodies.
 */
public class ValidInputGenerator {

    private final GenerationConfig config;
    private final Random random;

    public ValidInputGenerator(GenerationConfig config, Random random) {
        this.config = config != null ? config : GenerationConfig.defaultConfig();
        this.random = random != null ? random : new Random(this.config.getSeed());
    }

    /**
     * Generates a valid value for an API parameter.
     */
    public Object generateParameterValue(ApiParameter parameter) {
        if (parameter == null || parameter.getSchema() == null) {
            return "valid_param";
        }
        return generateValidValue(parameter.getSchema(), 0, GenerationStrategy.SCHEMA_VALID_FULL);
    }

    /**
     * Generates a valid payload for a schema under the specified valid strategy.
     */
    public Object generateValidValue(ApiSchema schema, int depth, GenerationStrategy strategy) {
        if (schema == null) {
            return "valid_data";
        }

        if (schema.isCircular() || depth >= config.getMaxNestedDepth()) {
            return schema.getType() == SchemaType.ARRAY ? List.of() : Map.of();
        }

        // Enums have highest priority for valid generation
        if (!schema.getEnumValues().isEmpty()) {
            List<String> enums = schema.getEnumValues();
            int idx = Math.abs(random.nextInt()) % enums.size();
            return castEnumValue(enums.get(idx), schema.getType());
        }

        SchemaType type = schema.getType();
        return switch (type) {
            case STRING -> generateValidString(schema);
            case INTEGER -> generateValidInteger(schema);
            case NUMBER -> generateValidNumber(schema);
            case BOOLEAN -> random.nextBoolean();
            case OBJECT -> generateValidObject(schema, depth, strategy);
            case ARRAY -> generateValidArray(schema, depth, strategy);
            case ANY -> generateValidString(schema);
        };
    }

    private Object generateValidString(ApiSchema schema) {
        String format = schema.getFormat() != null ? schema.getFormat().toLowerCase(Locale.ROOT) : "";

        String baseValue = switch (format) {
            case "email" -> "user" + (Math.abs(random.nextInt()) % 9000 + 1000) + "@example.com";
            case "uuid" -> UUID.nameUUIDFromBytes(("seed-" + random.nextLong()).getBytes()).toString();
            case "date-time" -> "2026-11-04T12:00:00Z";
            case "date" -> "2026-11-04";
            case "time" -> "12:00:00";
            case "uri", "url" -> "https://example.com/api/v1/resource";
            case "ipv4" -> "192.0.2." + (Math.abs(random.nextInt()) % 250 + 1);
            case "ipv6" -> "2001:db8::" + Integer.toHexString(Math.abs(random.nextInt()) % 65535);
            case "hostname" -> "api.example.com";
            case "byte", "binary" -> "dGVzdC1kYXRh";
            case "password" -> "P@ssw0rd!" + (Math.abs(random.nextInt()) % 900 + 100);
            default -> generatePatternOrText(schema);
        };

        // Enforce minLength and maxLength
        if (schema.getMinLength() != null && baseValue.length() < schema.getMinLength()) {
            baseValue = baseValue + "a".repeat(schema.getMinLength() - baseValue.length());
        }
        if (schema.getMaxLength() != null && baseValue.length() > schema.getMaxLength()) {
            baseValue = baseValue.substring(0, schema.getMaxLength());
        }

        return baseValue;
    }

    private String generatePatternOrText(ApiSchema schema) {
        String pattern = schema.getPattern();
        if (pattern != null && !pattern.isBlank()) {
            if (pattern.contains("\\+") || pattern.contains("phone") || pattern.contains("\\d")) {
                return "+15550192834";
            }
            if (pattern.contains("^[a-zA-Z0-9]+$") || pattern.contains("alphanumeric")) {
                return "AlphaNum" + (Math.abs(random.nextInt()) % 900 + 100);
            }
        }
        return "sample_text_" + (Math.abs(random.nextInt()) % 1000);
    }

    private Long generateValidInteger(ApiSchema schema) {
        long min = schema.getMinimum() != null ? schema.getMinimum().longValue() : 1L;
        if (schema.isExclusiveMinimum() && schema.getMinimum() != null) {
            min++;
        }

        long max = schema.getMaximum() != null ? schema.getMaximum().longValue() : 100L;
        if (schema.isExclusiveMaximum() && schema.getMaximum() != null) {
            max--;
        }

        if (min > max) {
            long temp = min;
            min = max;
            max = temp;
        }

        if (min == max) {
            return min;
        }

        long diff = Math.max(1, (max - min) + 1);
        long offset = Math.abs(random.nextLong()) % diff;
        return min + offset;
    }

    private BigDecimal generateValidNumber(ApiSchema schema) {
        BigDecimal min = schema.getMinimum() != null ? schema.getMinimum() : BigDecimal.valueOf(1.0);
        BigDecimal max = schema.getMaximum() != null ? schema.getMaximum() : BigDecimal.valueOf(100.0);

        if (schema.isExclusiveMinimum() && schema.getMinimum() != null) {
            min = min.add(BigDecimal.valueOf(0.1));
        }
        if (schema.isExclusiveMaximum() && schema.getMaximum() != null) {
            max = max.subtract(BigDecimal.valueOf(0.1));
        }

        if (min.compareTo(max) > 0) {
            BigDecimal temp = min;
            min = max;
            max = temp;
        }

        if (min.compareTo(max) == 0) {
            return min;
        }

        BigDecimal delta = max.subtract(min);
        double factor = random.nextDouble();
        BigDecimal val = min.add(delta.multiply(BigDecimal.valueOf(factor))).setScale(2, RoundingMode.HALF_UP);
        return val;
    }

    private Map<String, Object> generateValidObject(ApiSchema schema, int depth, GenerationStrategy strategy) {
        Map<String, Object> result = new LinkedHashMap<>();
        Map<String, ApiSchema> props = schema.getProperties();

        if (props == null || props.isEmpty()) {
            return result;
        }

        for (Map.Entry<String, ApiSchema> entry : props.entrySet()) {
            String propName = entry.getKey();
            ApiSchema propSchema = entry.getValue();
            boolean isRequired = schema.isRequired(propName);

            boolean shouldInclude = switch (strategy) {
                case SCHEMA_VALID_MINIMAL -> isRequired;
                case SCHEMA_VALID_FULL -> true;
                case SCHEMA_VALID_RANDOM -> isRequired || (random.nextDouble() < config.getOptionalFieldProbability());
                default -> true;
            };

            if (shouldInclude) {
                Object val = generateValidValue(propSchema, depth + 1, strategy);
                result.put(propName, val);
            }
        }

        return result;
    }

    private List<Object> generateValidArray(ApiSchema schema, int depth, GenerationStrategy strategy) {
        List<Object> list = new ArrayList<>();
        ApiSchema itemsSchema = schema.getItems() != null ? schema.getItems() : ApiSchema.ofType(SchemaType.STRING);

        int minItems = schema.getMinItems() != null ? schema.getMinItems() : 1;
        int maxItems = schema.getMaxItems() != null ? schema.getMaxItems() : config.getMaxArrayElements();
        int count = Math.min(Math.max(minItems, 1), Math.max(minItems, maxItems));
        count = Math.min(count, config.getMaxArrayElements());

        for (int i = 0; i < count; i++) {
            list.add(generateValidValue(itemsSchema, depth + 1, strategy));
        }

        return list;
    }

    private Object castEnumValue(String strVal, SchemaType type) {
        if (type == SchemaType.INTEGER) {
            try { return Long.parseLong(strVal); } catch (Exception ignored) {}
        } else if (type == SchemaType.NUMBER) {
            try { return Double.parseDouble(strVal); } catch (Exception ignored) {}
        } else if (type == SchemaType.BOOLEAN) {
            return Boolean.parseBoolean(strVal);
        }
        return strVal;
    }
}

