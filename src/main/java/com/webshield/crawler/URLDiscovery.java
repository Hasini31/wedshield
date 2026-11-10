package com.webshield.crawler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.URI;
import java.util.Locale;
import java.util.Set;

/**
 * Validates discovered URLs against scope boundaries and security policies (e.g. SSRF prevention).
 */
public class URLDiscovery {

    private static final Logger log = LoggerFactory.getLogger(URLDiscovery.class);

    private static final Set<String> IGNORED_EXTENSIONS = Set.of(
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp", ".webp",
            ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar", ".exe", ".bin",
            ".mp3", ".mp4", ".avi", ".mkv", ".mov",
            ".woff", ".woff2", ".ttf", ".eot",
            ".css" // CSS files are not crawled as web pages
    );

    private final String targetDomain;
    private final boolean allowLocalhost;

    public URLDiscovery(String targetDomain, boolean allowLocalhost) {
        this.targetDomain = targetDomain != null ? targetDomain.toLowerCase(Locale.ROOT) : "";
        this.allowLocalhost = allowLocalhost;
    }

    /**
     * Checks if a normalized URL is safe and within the target crawling scope.
     */
    public boolean isInScope(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }

        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host == null) {
                return false;
            }

            host = host.toLowerCase(Locale.ROOT);

            // Scope domain check
            if (!isDomainMatch(host, targetDomain)) {
                return false;
            }

            // Binary / static media extension filter
            String path = uri.getPath();
            if (path != null) {
                String lowerPath = path.toLowerCase(Locale.ROOT);
                for (String ext : IGNORED_EXTENSIONS) {
                    if (lowerPath.endsWith(ext)) {
                        return false;
                    }
                }
            }

            // Defensive SSRF & Private Network Check
            if (!allowLocalhost && isPrivateOrLocalAddress(host)) {
                log.warn("Blocked crawling of private or loopback destination: {}", host);
                return false;
            }

            return true;
        } catch (Exception e) {
            log.trace("URL rejected by scope check: {}", url);
            return false;
        }
    }

    private boolean isDomainMatch(String host, String target) {
        if (target.isEmpty()) return false;
        // Strip port if present in target
        int colon = target.indexOf(':');
        if (colon > 0) target = target.substring(0, colon);

        return host.equals(target) || host.endsWith("." + target);
    }

    private boolean isPrivateOrLocalAddress(String host) {
        if (host.equalsIgnoreCase("localhost") || host.endsWith(".localhost") || host.equalsIgnoreCase("127.0.0.1")) {
            return true;
        }

        try {
            InetAddress addr = InetAddress.getByName(host);
            return addr.isLoopbackAddress() ||
                   addr.isSiteLocalAddress() ||
                   addr.isLinkLocalAddress() ||
                   addr.isAnyLocalAddress();
        } catch (Exception e) {
            return false;
        }
    }
}

