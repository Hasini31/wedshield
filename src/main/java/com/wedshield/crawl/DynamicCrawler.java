package com.wedshield.crawl;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DynamicCrawler {
    private static final Pattern HREF_PATTERN = Pattern.compile("href\\s*=\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);

    public List<String> crawl(String baseUrl, String html) {
        if (html == null || html.isBlank()) {
            return List.of(baseUrl);
        }

        Set<String> discovered = new LinkedHashSet<>();
        discovered.add(baseUrl);

        Matcher matcher = HREF_PATTERN.matcher(html);
        while (matcher.find()) {
            String href = matcher.group(1);
            URI resolved = URI.create(baseUrl).resolve(href);
            if (resolved.getHost() != null && resolved.getHost().equalsIgnoreCase(URI.create(baseUrl).getHost())) {
                discovered.add(resolved.toString());
            }
        }

        return new ArrayList<>(discovered);
    }
}
