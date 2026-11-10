package com.webshield.api.models;

/**
 * Representation of an HTTP parameter (path, query, header, or cookie).
 */
public class ApiParameter {

    private String name;
    private ParameterLocation location = ParameterLocation.QUERY;
    private String description;
    private boolean required = false;
    private boolean deprecated = false;
    private ApiSchema schema = new ApiSchema();
    private Object example;

    public ApiParameter() {
    }

    public ApiParameter(String name, ParameterLocation location, boolean required, ApiSchema schema) {
        this.name = name;
        this.location = location != null ? location : ParameterLocation.QUERY;
        this.required = required;
        this.schema = schema != null ? schema : new ApiSchema();
    }

    public ApiParameter(String name, ParameterLocation location, String description,
                        boolean required, boolean deprecated, ApiSchema schema, Object example) {
        this.name = name;
        this.location = location != null ? location : ParameterLocation.QUERY;
        this.description = description;
        this.required = required;
        this.deprecated = deprecated;
        this.schema = schema != null ? schema : new ApiSchema();
        this.example = example;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public ParameterLocation getLocation() {
        return location;
    }

    public void setLocation(ParameterLocation location) {
        this.location = location != null ? location : ParameterLocation.QUERY;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isRequired() {
        return required;
    }

    public void setRequired(boolean required) {
        this.required = required;
    }

    public boolean isDeprecated() {
        return deprecated;
    }

    public void setDeprecated(boolean deprecated) {
        this.deprecated = deprecated;
    }

    public ApiSchema getSchema() {
        return schema;
    }

    public void setSchema(ApiSchema schema) {
        this.schema = schema != null ? schema : new ApiSchema();
    }

    public Object getExample() {
        return example;
    }

    public void setExample(Object example) {
        this.example = example;
    }

    @Override
    public String toString() {
        return "ApiParameter{" +
                "name='" + name + '\'' +
                ", location=" + location +
                ", required=" + required +
                '}';
    }
}

