package com.webshield.crawler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

/**
 * Normalizes URLs to standard canonical form to prevent crawl loops and duplicates.
 * Based on the URL canonicalization principles found in OWASP ZAP's {@code URLCanonicalizer}.
 */
public class URLNormalizer {

    private static final Logger log = LoggerFactory.getLogger(URLNormalizer.class);

    /**
     * Resolves a potentially relative URL against a base URL, normalizes it, and strips fragments.
     */
    public Optional<String> normalize(String rawUrl, String baseUrl) {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            return Optional.empty();
        }

        String candidate = rawUrl.trim();

        // Filter out non-http protocols (javascript:, mailto:, tel:, data:)
        String lowerCandidate = candidate.toLowerCase(Locale.ROOT);
        if (lowerCandidate.startsWith("javascript:") ||
            lowerCandidate.startsWith("mailto:") ||
            lowerCandidate.startsWith("tel:") ||
            lowerCandidate.startsWith("data:") ||
            lowerCandidate.startsWith("#")) {
            return Optional.empty();
        }

        try {
            URI resolved;
            if (baseUrl != null && !baseUrl.trim().isEmpty()) {
                URI baseUri = new URI(baseUrl.trim());
                resolved = baseUri.resolve(candidate);
            } else {
                resolved = new URI(candidate);
            }

            String scheme = resolved.getScheme();
            if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
                return Optional.empty();
            }

            String host = resolved.getHost();
            if (host == null || host.trim().isEmpty()) {
                return Optional.empty();
            }

            int port = resolved.getPort();
            // Default port elimination
            if ((scheme.equalsIgnoreCase("http") && port == 80) ||
                (scheme.equalsIgnoreCase("https") && port == 443)) {
                port = -1;
            }

            String path = resolved.getPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            } else if (path.length() > 1 && path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }

            // Canonicalize query parameter ordering
            String query = canonicalizeQuery(resolved.getQuery());

            URI normalized = new URI(
                    scheme.toLowerCase(Locale.ROOT),
                    resolved.getUserInfo(),
                    host.toLowerCase(Locale.ROOT),
                    port,
                    path,
                    query,
                    null // strip fragment
            );

            return Optional.of(normalized.toString());
        } catch (URISyntaxException e) {
            log.trace("Failed to normalize URL '{}' against base '{}': {}", candidate, baseUrl, e.getMessage());
            return Optional.empty();
        }
    }

    private String canonicalizeQuery(String query) {
        if (query == null || query.trim().isEmpty()) {
            return null;
        }

        String[] pairs = query.split("&");
        List<String> sortedPairs = new ArrayList<>(Arrays.asList(pairs));
        Collections.sort(sortedPairs);

        return String.join("&", sortedPairs);
    }
}

