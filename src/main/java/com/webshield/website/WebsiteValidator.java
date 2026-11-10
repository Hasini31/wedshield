package com.webshield.website;

import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Validates website registration and editing inputs.
 */
@Component
public class WebsiteValidator {

    /**
     * Validates all registration attributes.
     * Throws {@link IllegalArgumentException} with a descriptive message upon failure.
     */
    public void validate(String name, String url, boolean authorized) {
        validateName(name);
        validateUrl(url);
        validateAuthorization(authorized);
    }

    public void validateName(String name) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Website name cannot be empty.");
        }
        if (name.trim().length() > 120) {
            throw new IllegalArgumentException("Website name cannot exceed 120 characters.");
        }
    }

    public URI validateUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("Website URL cannot be empty.");
        }

        String trimmed = url.trim();
        URI uri;
        try {
            uri = new URI(trimmed);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid website URL format: " + e.getMessage());
        }

        String scheme = uri.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
            throw new IllegalArgumentException("Only HTTP and HTTPS URL schemes are permitted.");
        }

        if (uri.getHost() == null || uri.getHost().trim().isEmpty()) {
            throw new IllegalArgumentException("URL must specify a valid host/domain name.");
        }

        return uri;
    }

    public void validateAuthorization(boolean authorized) {
        if (!authorized) {
            throw new IllegalArgumentException("You must explicitly confirm authorization to assess this target.");
        }
    }

    /**
     * Normalizes root website URL string (lowercase scheme and host, stripped fragment).
     */
    public String normalizeWebsiteUrl(String url) {
        URI uri = validateUrl(url);
        try {
            String path = uri.getPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            URI normalized = new URI(
                    uri.getScheme().toLowerCase(),
                    uri.getUserInfo(),
                    uri.getHost().toLowerCase(),
                    uri.getPort(),
                    path,
                    uri.getQuery(),
                    null // strip fragment
            );
            return normalized.toString();
        } catch (URISyntaxException e) {
            return url.trim();
        }
    }
}

