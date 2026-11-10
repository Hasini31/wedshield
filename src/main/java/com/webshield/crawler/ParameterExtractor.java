package com.webshield.crawler;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Extracts query and form parameter names and default values.
 */
public class ParameterExtractor {

    /**
     * Extracts query parameters from a URL into a Map of parameter name to list of values.
     */
    public Map<String, List<String>> extractQueryParameters(String url) {
        if (url == null || !url.contains("?")) {
            return Collections.emptyMap();
        }

        Map<String, List<String>> params = new LinkedHashMap<>();
        try {
            URI uri = new URI(url);
            String query = uri.getRawQuery();
            if (query == null || query.isEmpty()) {
                return Collections.emptyMap();
            }

            String[] pairs = query.split("&");
            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8) : pair;
                String value = idx > 0 && pair.length() > idx + 1
                        ? URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8) : "";

                params.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
            }
        } catch (Exception ignored) {}

        return Collections.unmodifiableMap(params);
    }

    /**
     * Extracts field names and default/sample values from a discovered form.
     */
    public Map<String, String> extractFormParameters(DiscoveredForm form) {
        if (form == null || form.getFields().isEmpty()) {
            return Collections.emptyMap();
        }

        Map<String, String> params = new LinkedHashMap<>();
        for (DiscoveredField field : form.getFields()) {
            if (field.getName() != null && !field.getName().isEmpty()) {
                // Ignore submit buttons without meaningful values
                if (!"submit".equalsIgnoreCase(field.getType()) && !"button".equalsIgnoreCase(field.getType())) {
                    params.put(field.getName(), field.getPlaceholder() != null ? field.getPlaceholder() : "test");
                }
            }
        }
        return Collections.unmodifiableMap(params);
    }
}

