package com.webshield.crawler;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Encapsulates an HTML form discovered during crawling.
 */
public class DiscoveredForm {

    private long id;
    private long pageId;
    private final String formAction;
    private final String formMethod;
    private final String formId;
    private final String formName;
    private final List<DiscoveredField> fields;

    public DiscoveredForm(String formAction, String formMethod, String formId, String formName) {
        this.formAction = formAction;
        this.formMethod = formMethod != null ? formMethod.toUpperCase(Locale.ROOT) : "GET";
        this.formId = formId;
        this.formName = formName;
        this.fields = new ArrayList<>();
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }
    public long getPageId() { return pageId; }
    public void setPageId(long pageId) { this.pageId = pageId; }

    public String getFormAction() { return formAction; }
    public String getFormMethod() { return formMethod; }
    public String getFormId() { return formId; }
    public String getFormName() { return formName; }
    public List<DiscoveredField> getFields() { return Collections.unmodifiableList(fields); }

    public void addField(DiscoveredField field) {
        if (field != null) {
            this.fields.add(field);
        }
    }

    public int getFieldCount() {
        return fields.size();
    }

    @Override
    public String toString() {
        return formMethod + " " + formAction + " (" + fields.size() + " fields)";
    }
}

