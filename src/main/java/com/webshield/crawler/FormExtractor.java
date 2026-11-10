package com.webshield.crawler;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Extracts HTML form structures and input field metadata using Jsoup.
 * Modeled after OWASP ZAP's {@code SpiderHtmlFormParser}.
 */
public class FormExtractor {

    private final URLNormalizer normalizer;

    public FormExtractor() {
        this(new URLNormalizer());
    }

    public FormExtractor(URLNormalizer normalizer) {
        this.normalizer = normalizer;
    }

    /**
     * Extracts all HTML forms and their input parameters from a web page.
     */
    public List<DiscoveredForm> extractForms(String htmlContent, String pageUrl) {
        if (htmlContent == null || htmlContent.trim().isEmpty()) {
            return Collections.emptyList();
        }

        List<DiscoveredForm> forms = new ArrayList<>();
        try {
            Document doc = Jsoup.parse(htmlContent, pageUrl);
            Elements formElements = doc.select("form");

            for (Element formEl : formElements) {
                String rawAction = formEl.attr("action");
                String actionUrl = normalizer.normalize(rawAction != null && !rawAction.isEmpty() ? rawAction : pageUrl, pageUrl)
                        .orElse(pageUrl);

                String method = formEl.attr("method");
                if (method == null || method.trim().isEmpty()) {
                    method = "GET";
                }

                String formId = formEl.attr("id");
                String formName = formEl.attr("name");

                DiscoveredForm form = new DiscoveredForm(actionUrl, method.toUpperCase(Locale.ROOT), formId, formName);

                // 1. <input> elements
                Elements inputs = formEl.select("input");
                for (Element input : inputs) {
                    String name = input.attr("name");
                    String type = input.attr("type");
                    if (type == null || type.isEmpty()) type = "text";
                    String fieldId = input.attr("id");
                    String placeholder = input.attr("placeholder");
                    boolean required = input.hasAttr("required");
                    boolean hasMax = input.hasAttr("maxlength");
                    boolean hasPattern = input.hasAttr("pattern");

                    form.addField(new DiscoveredField(name, type, fieldId, placeholder, required, hasMax, hasPattern));
                }

                // 2. <textarea> elements
                Elements textareas = formEl.select("textarea");
                for (Element ta : textareas) {
                    String name = ta.attr("name");
                    String fieldId = ta.attr("id");
                    String placeholder = ta.attr("placeholder");
                    boolean required = ta.hasAttr("required");
                    boolean hasMax = ta.hasAttr("maxlength");

                    form.addField(new DiscoveredField(name, "textarea", fieldId, placeholder, required, hasMax, false));
                }

                // 3. <select> elements
                Elements selects = formEl.select("select");
                for (Element sel : selects) {
                    String name = sel.attr("name");
                    String fieldId = sel.attr("id");
                    boolean required = sel.hasAttr("required");

                    form.addField(new DiscoveredField(name, "select", fieldId, null, required, false, false));
                }

                // 4. <button type="submit">
                Elements buttons = formEl.select("button[name]");
                for (Element btn : buttons) {
                    String name = btn.attr("name");
                    String type = btn.attr("type");
                    if (type == null || type.isEmpty()) type = "submit";
                    String fieldId = btn.attr("id");

                    form.addField(new DiscoveredField(name, type, fieldId, null, false, false, false));
                }

                forms.add(form);
            }
        } catch (Exception ignored) {}

        return forms;
    }
}

