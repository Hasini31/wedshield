package com.webshield.http;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

/**
 * Validates and resolves HTTP redirect targets to ensure they remain within authorized target scope.
 */
public class RedirectHandler {

    private static final Logger log = LoggerFactory.getLogger(RedirectHandler.class);

    /**
     * Determines whether a response is a redirect and returns the resolved safe target URI if valid.
     *
     * @param originalUrl  The original request URL.
     * @param response     The HTTP response.
     * @param targetDomain Approved base domain for the scan target.
     * @return Optional containing the resolved redirect target URL, or empty if not a redirect or out-of-scope.
     */
    public Optional<String> resolveRedirect(String originalUrl, HttpResponseData response, String targetDomain) {
        if (response == null || !response.isRedirect()) {
            return Optional.empty();
        }

        Optional<String> locationOpt = response.getFirstHeader("Location");
        if (locationOpt.isEmpty() || locationOpt.get().trim().isEmpty()) {
            return Optional.empty();
        }

        String location = locationOpt.get().trim();
        try {
            URI baseUri = new URI(originalUrl);
            URI resolvedUri = baseUri.resolve(location);

            // Scheme validation
            String scheme = resolvedUri.getScheme();
            if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
                log.warn("Blocked redirect to non-HTTP scheme: {}", resolvedUri);
                return Optional.empty();
            }

            // Scope validation if targetDomain is specified
            if (targetDomain != null && !targetDomain.isBlank()) {
                String host = resolvedUri.getHost();
                if (host == null || !isDomainInScope(host, targetDomain)) {
                    log.warn("Blocked redirect out-of-scope: {} -> {} (target domain: {})",
                            originalUrl, resolvedUri, targetDomain);
                    return Optional.empty();
                }
            }

            return Optional.of(resolvedUri.toString());
        } catch (URISyntaxException e) {
            log.warn("Failed to resolve redirect URI from {} with location {}: {}", originalUrl, location, e.getMessage());
            return Optional.empty();
        }
    }

    public boolean isDomainInScope(String host, String targetDomain) {
        if (host == null || targetDomain == null) return false;
        String h = host.toLowerCase();
        String t = targetDomain.toLowerCase();
        // Remove port if present
        int colon = t.indexOf(':');
        if (colon > 0) t = t.substring(0, colon);

        int hColon = h.indexOf(':');
        if (hColon > 0) h = h.substring(0, hColon);

        return h.equals(t) || h.endsWith("." + t);
    }
}

