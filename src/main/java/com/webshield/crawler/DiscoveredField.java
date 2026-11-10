package com.webshield.crawler;

/**
 * Encapsulates an HTML form input field discovered on a crawled page.
 */
public class DiscoveredField {

    private long id;
    private long formId;
    private final String name;
    private final String type;
    private final String fieldId;
    private final String placeholder;
    private final boolean required;
    private final boolean hasMaxlength;
    private final boolean hasPattern;

    public DiscoveredField(String name, String type, String fieldId, String placeholder,
                           boolean required, boolean hasMaxlength, boolean hasPattern) {
        this.name = name != null ? name : "";
        this.type = type != null ? type.toLowerCase() : "text";
        this.fieldId = fieldId;
        this.placeholder = placeholder;
        this.required = required;
        this.hasMaxlength = hasMaxlength;
        this.hasPattern = hasPattern;
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }
    public long getFormId() { return formId; }
    public void setFormId(long formId) { this.formId = formId; }

    public String getName() { return name; }
    public String getType() { return type; }
    public String getFieldId() { return fieldId; }
    public String getPlaceholder() { return placeholder; }
    public boolean isRequired() { return required; }
    public boolean isHasMaxlength() { return hasMaxlength; }
    public boolean isHasPattern() { return hasPattern; }

    @Override
    public String toString() {
        return name + " (" + type + (required ? ", required" : "") + ")";
    }
}

