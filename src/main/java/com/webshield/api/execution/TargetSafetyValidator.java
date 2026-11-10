package com.webshield.api.execution;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Set;

/**
 * Defensive safety and anti-SSRF validator for API test execution targets and redirect destinations.
 * Blocks cloud metadata, private/internal IP ranges, loopback, and unauthorized URI schemes.
 */
public class TargetSafetyValidator {

    private static final Logger log = LoggerFactory.getLogger(TargetSafetyValidator.class);

    private static final Set<String> CLOUD_METADATA_HOSTS = Set.of(
            "169.254.169.254",
            "metadata.google.internal",
            "169.254.169.250",
            "fd00:ec2::254"
    );

    /**
     * Validates that the target URI satisfies strict security boundaries.
     *
     * @param uri                  Target URI to validate.
     * @param allowLocalAddresses  Whether local addresses (127.0.0.1, localhost) are permitted (for test fixtures).
     * @param targetDomainScope    Optional authorized base domain scope.
     * @throws SecurityException If the URI violates security boundaries.
     */
    public void validateTarget(URI uri, boolean allowLocalAddresses, String targetDomainScope) {
        if (uri == null) {
            throw new IllegalArgumentException("Target URI cannot be null");
        }

        // 1. Strict Scheme Verification
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new IllegalArgumentException("Target URI must specify a scheme (http or https)");
        }
        String lowerScheme = scheme.toLowerCase(Locale.ROOT);
        if (!lowerScheme.equals("http") && !lowerScheme.equals("https")) {
            throw new SecurityException("Unsupported URI scheme '" + scheme + "'. Only HTTP and HTTPS are permitted.");
        }

        // 2. Host Verification
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Target URI must contain a valid hostname");
        }
        String lowerHost = host.toLowerCase(Locale.ROOT);

        // 3. Cloud Metadata Protection
        if (CLOUD_METADATA_HOSTS.contains(lowerHost) || lowerHost.endsWith(".metadata.google.internal")) {
            log.error("SSRF attempt blocked: access to cloud metadata host '{}' is prohibited", lowerHost);
            throw new SecurityException("Access to cloud metadata endpoints is strictly prohibited");
        }

        // 4. Local and Private Address Protection
        boolean isExplicitLocalName = lowerHost.equals("localhost")
                || lowerHost.equals("127.0.0.1")
                || lowerHost.equals("::1")
                || lowerHost.equals("0.0.0.0");

        if (isExplicitLocalName && !allowLocalAddresses) {
            log.warn("Blocked request to local host '{}' (allowLocalAddresses=false)", lowerHost);
            throw new SecurityException("Access to loopback/local address '" + lowerHost + "' is blocked by security policy");
        }

        // Inspect resolved IP address if not allowing local addresses
        if (!allowLocalAddresses) {
            try {
                InetAddress addr = InetAddress.getByName(host);
                if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()
                        || addr.isMulticastAddress() || addr.isAnyLocalAddress()) {
                    log.warn("Blocked request to private/internal IP '{}' ({})", lowerHost, addr.getHostAddress());
                    throw new SecurityException("Access to private/local network address '" + addr.getHostAddress() + "' is blocked by security policy");
                }
            } catch (UnknownHostException e) {
                // If hostname cannot be resolved, let execution fail naturally at connect time,
                // or if it's already an IP address, catch format issues.
                log.debug("Host resolution check for '{}': {}", lowerHost, e.getMessage());
            }
        }

        // 5. Target Scope Verification (if specified)
        if (targetDomainScope != null && !targetDomainScope.isBlank()) {
            String cleanTarget = targetDomainScope.toLowerCase(Locale.ROOT);
            int colon = cleanTarget.indexOf(':');
            if (colon > 0) cleanTarget = cleanTarget.substring(0, colon);

            if (!lowerHost.equals(cleanTarget) && !lowerHost.endsWith("." + cleanTarget)) {
                log.warn("Target host '{}' is outside authorized domain scope '{}'", lowerHost, cleanTarget);
                throw new SecurityException("Target host '" + lowerHost + "' is outside authorized scope '" + cleanTarget + "'");
            }
        }
    }
}
