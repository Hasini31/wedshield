package com.webshield.api.models;

import java.math.BigDecimal;
import java.util.*;

/**
 * Strongly-typed internal representation of an OpenAPI / JSON Schema.
 * Preserves structural hierarchies, validation constraints, and detects circular references.
 */
public class ApiSchema {

    private SchemaType type = SchemaType.ANY;
    private String format;
    private String title;
    private String description;
    private boolean nullable = false;
    private Object defaultValue;
    private Object example;

    // String constraints
    private Integer minLength;
    private Integer maxLength;
    private String pattern;

    // Numeric constraints
    private BigDecimal minimum;
    private BigDecimal maximum;
    private boolean exclusiveMinimum = false;
    private boolean exclusiveMaximum = false;

    // Array constraints
    private Integer minItems;
    private Integer maxItems;
    private boolean uniqueItems = false;
    private ApiSchema items;

    // Object constraints
    private Map<String, ApiSchema> properties = new LinkedHashMap<>();
    private Set<String> requiredProperties = new LinkedHashSet<>();
    private boolean additionalPropertiesAllowed = true;
    private ApiSchema additionalPropertiesSchema;

    // Polymorphism / Composition
    private List<ApiSchema> oneOf = new ArrayList<>();
    private List<ApiSchema> anyOf = new ArrayList<>();
    private List<ApiSchema> allOf = new ArrayList<>();

    // Enum
    private List<String> enumValues = new ArrayList<>();

    // References & Recursion
    private String ref;
    private boolean circular = false;

    public ApiSchema() {
    }

    public static ApiSchema circular(String ref, SchemaType fallbackType) {
        ApiSchema schema = new ApiSchema();
        schema.setRef(ref);
        schema.setCircular(true);
        schema.setType(fallbackType != null ? fallbackType : SchemaType.OBJECT);
        schema.setDescription("Circular reference to " + ref);
        return schema;
    }

    public static ApiSchema ofType(SchemaType type) {
        ApiSchema schema = new ApiSchema();
        schema.setType(type);
        return schema;
    }

    // Convenience checks
    public boolean isString() { return type == SchemaType.STRING; }
    public boolean isInteger() { return type == SchemaType.INTEGER; }
    public boolean isNumber() { return type == SchemaType.NUMBER || type == SchemaType.INTEGER; }
    public boolean isBoolean() { return type == SchemaType.BOOLEAN; }
    public boolean isObject() { return type == SchemaType.OBJECT; }
    public boolean isArray() { return type == SchemaType.ARRAY; }
    public boolean isRequired(String propertyName) {
        return requiredProperties.contains(propertyName);
    }

    public ApiSchema getProperty(String name) {
        return properties.get(name);
    }

    // Getters and Setters
    public SchemaType getType() { return type; }
    public void setType(SchemaType type) { this.type = type != null ? type : SchemaType.ANY; }

    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public boolean isNullable() { return nullable; }
    public void setNullable(boolean nullable) { this.nullable = nullable; }

    public Object getDefaultValue() { return defaultValue; }
    public void setDefaultValue(Object defaultValue) { this.defaultValue = defaultValue; }

    public Object getExample() { return example; }
    public void setExample(Object example) { this.example = example; }

    public Integer getMinLength() { return minLength; }
    public void setMinLength(Integer minLength) { this.minLength = minLength; }

    public Integer getMaxLength() { return maxLength; }
    public void setMaxLength(Integer maxLength) { this.maxLength = maxLength; }

    public String getPattern() { return pattern; }
    public void setPattern(String pattern) { this.pattern = pattern; }

    public BigDecimal getMinimum() { return minimum; }
    public void setMinimum(BigDecimal minimum) { this.minimum = minimum; }

    public BigDecimal getMaximum() { return maximum; }
    public void setMaximum(BigDecimal maximum) { this.maximum = maximum; }

    public boolean isExclusiveMinimum() { return exclusiveMinimum; }
    public void setExclusiveMinimum(boolean exclusiveMinimum) { this.exclusiveMinimum = exclusiveMinimum; }

    public boolean isExclusiveMaximum() { return exclusiveMaximum; }
    public void setExclusiveMaximum(boolean exclusiveMaximum) { this.exclusiveMaximum = exclusiveMaximum; }

    public Integer getMinItems() { return minItems; }
    public void setMinItems(Integer minItems) { this.minItems = minItems; }

    public Integer getMaxItems() { return maxItems; }
    public void setMaxItems(Integer maxItems) { this.maxItems = maxItems; }

    public boolean isUniqueItems() { return uniqueItems; }
    public void setUniqueItems(boolean uniqueItems) { this.uniqueItems = uniqueItems; }

    public ApiSchema getItems() { return items; }
    public void setItems(ApiSchema items) { this.items = items; }

    public Map<String, ApiSchema> getProperties() { return Collections.unmodifiableMap(properties); }
    public void setProperties(Map<String, ApiSchema> properties) {
        this.properties = properties != null ? new LinkedHashMap<>(properties) : new LinkedHashMap<>();
    }
    public void addProperty(String name, ApiSchema schema) {
        this.properties.put(name, schema);
    }

    public Set<String> getRequiredProperties() { return Collections.unmodifiableSet(requiredProperties); }
    public void setRequiredProperties(Set<String> requiredProperties) {
        this.requiredProperties = requiredProperties != null ? new LinkedHashSet<>(requiredProperties) : new LinkedHashSet<>();
    }
    public void addRequiredProperty(String propertyName) {
        if (propertyName != null && !propertyName.isBlank()) {
            this.requiredProperties.add(propertyName.trim());
        }
    }

    public boolean isAdditionalPropertiesAllowed() { return additionalPropertiesAllowed; }
    public void setAdditionalPropertiesAllowed(boolean allowed) { this.additionalPropertiesAllowed = allowed; }

    public ApiSchema getAdditionalPropertiesSchema() { return additionalPropertiesSchema; }
    public void setAdditionalPropertiesSchema(ApiSchema schema) { this.additionalPropertiesSchema = schema; }

    public List<ApiSchema> getOneOf() { return Collections.unmodifiableList(oneOf); }
    public void setOneOf(List<ApiSchema> oneOf) { this.oneOf = oneOf != null ? new ArrayList<>(oneOf) : new ArrayList<>(); }

    public List<ApiSchema> getAnyOf() { return Collections.unmodifiableList(anyOf); }
    public void setAnyOf(List<ApiSchema> anyOf) { this.anyOf = anyOf != null ? new ArrayList<>(anyOf) : new ArrayList<>(); }

    public List<ApiSchema> getAllOf() { return Collections.unmodifiableList(allOf); }
    public void setAllOf(List<ApiSchema> allOf) { this.allOf = allOf != null ? new ArrayList<>(allOf) : new ArrayList<>(); }

    public List<String> getEnumValues() { return Collections.unmodifiableList(enumValues); }
    public void setEnumValues(List<String> enumValues) {
        this.enumValues = enumValues != null ? new ArrayList<>(enumValues) : new ArrayList<>();
    }
    public void addEnumValue(String value) {
        if (value != null) {
            this.enumValues.add(value);
        }
    }

    public String getRef() { return ref; }
    public void setRef(String ref) { this.ref = ref; }

    public boolean isCircular() { return circular; }
    public void setCircular(boolean circular) { this.circular = circular; }

    @Override
    public String toString() {
        return "ApiSchema{" +
                "type=" + type +
                (format != null ? ", format='" + format + '\'' : "") +
                (ref != null ? ", ref='" + ref + '\'' : "") +
                (circular ? ", circular=true" : "") +
                ", propertiesCount=" + properties.size() +
                '}';
    }
}

