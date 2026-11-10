package com.webshield.assessment.analyzers;

import com.webshield.assessment.AssessmentContext;
import com.webshield.assessment.AssessmentRule;
import com.webshield.assessment.models.AssessmentResult;
import com.webshield.assessment.models.ConfidenceLevel;
import com.webshield.assessment.models.Severity;
import com.webshield.crawler.DiscoveredPage;
import com.webshield.http.HttpResponseData;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Evaluates HTTP security headers against modern defensive standards.
 * Reference: OWASP Secure Headers Project & ZAP pscanrules.
 */
@Component
public class SecurityHeaderChecker implements AssessmentRule {

    @Override
    public String getRuleId() { return "WS-RULE-HEADERS"; }

    @Override
    public String getName() { return "HTTP Security Header Inspection"; }

    @Override
    public String getCategory() { return "Security Headers"; }

    @Override
    public List<AssessmentResult> analyze(AssessmentContext context, DiscoveredPage page, HttpResponseData response) {
        List<AssessmentResult> results = new ArrayList<>();
        if (response == null || !isHtmlOrText(response.getContentType())) {
            return results;
        }

        String url = page.getUrl();
        boolean isHttps = url.toLowerCase(Locale.ROOT).startsWith("https://");

        // 1. Content-Security-Policy
        Optional<String> csp = response.getFirstHeader("Content-Security-Policy");
        if (csp.isEmpty()) {
            results.add(new AssessmentResult(
                    "Missing Content-Security-Policy",
                    "Security Headers",
                    "WS-HDR-001",
                    url,
                    null,
                    page.getHttpMethod(),
                    Severity.HIGH,
                    ConfidenceLevel.CONFIRMED,
                    "The Content-Security-Policy (CSP) header is absent from the HTTP response. CSP restricts which sources of scripts, styles, and media the browser can load.",
                    "HTTP header 'Content-Security-Policy' was not found in response.",
                    "Passive Header Inspection",
                    "Configure a restrictive Content-Security-Policy response header (e.g., default-src 'self'; script-src 'self')."
            ));
        }

        // 2. Strict-Transport-Security (applicable for HTTPS)
        if (isHttps) {
            Optional<String> hsts = response.getFirstHeader("Strict-Transport-Security");
            if (hsts.isEmpty()) {
                results.add(new AssessmentResult(
                        "Missing Strict-Transport-Security",
                        "Security Headers",
                        "WS-HDR-002",
                        url,
                        null,
                        page.getHttpMethod(),
                        Severity.HIGH,
                        ConfidenceLevel.CONFIRMED,
                        "The HTTP Strict-Transport-Security (HSTS) header is missing on an HTTPS endpoint.",
                        "Endpoint is served over HTTPS but lacks 'Strict-Transport-Security' header.",
                        "Passive Header Inspection",
                        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses."
                ));
            }
        }

        // 3. X-Frame-Options (Clickjacking defense)
        Optional<String> xfo = response.getFirstHeader("X-Frame-Options");
        boolean hasCspFrameAncestors = csp.isPresent() && csp.get().toLowerCase(Locale.ROOT).contains("frame-ancestors");
        if (xfo.isEmpty() && !hasCspFrameAncestors) {
            results.add(new AssessmentResult(
                    "Missing X-Frame-Options",
                    "Security Headers",
                    "WS-HDR-003",
                    url,
                    null,
                    page.getHttpMethod(),
                    Severity.MEDIUM,
                    ConfidenceLevel.CONFIRMED,
                    "The X-Frame-Options header (and CSP frame-ancestors directive) is absent. Without framing protection, malicious sites can embed this page inside an iframe to conduct clickjacking attacks.",
                    "Neither 'X-Frame-Options' header nor CSP 'frame-ancestors' directive was detected.",
                    "Passive Header Inspection",
                    "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors 'self''."
            ));
        }

        // 4. X-Content-Type-Options
        Optional<String> xcto = response.getFirstHeader("X-Content-Type-Options");
        if (xcto.isEmpty() || !xcto.get().equalsIgnoreCase("nosniff")) {
            results.add(new AssessmentResult(
                    "Missing X-Content-Type-Options",
                    "Security Headers",
                    "WS-HDR-004",
                    url,
                    null,
                    page.getHttpMethod(),
                    Severity.LOW,
                    ConfidenceLevel.CONFIRMED,
                    "The X-Content-Type-Options header is missing or not set to 'nosniff'. Browsers may perform MIME-type sniffing on responses.",
                    "Header 'X-Content-Type-Options' is " + (xcto.isEmpty() ? "missing" : "set to '" + xcto.get() + "' instead of 'nosniff'"),
                    "Passive Header Inspection",
                    "Add 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing vulnerabilities."
            ));
        }

        // 5. Referrer-Policy
        Optional<String> rp = response.getFirstHeader("Referrer-Policy");
        if (rp.isEmpty()) {
            results.add(new AssessmentResult(
                    "Missing Referrer-Policy",
                    "Security Headers",
                    "WS-HDR-005",
                    url,
                    null,
                    page.getHttpMethod(),
                    Severity.LOW,
                    ConfidenceLevel.CONFIRMED,
                    "No Referrer-Policy header is present on this page. Sensitive URL paths and query parameters may leak in the Referer header to external origins.",
                    "Header 'Referrer-Policy' was not found in response.",
                    "Passive Header Inspection",
                    "Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
            ));
        }

        return results;
    }

    private boolean isHtmlOrText(String contentType) {
        if (contentType == null) return true;
        String lower = contentType.toLowerCase(Locale.ROOT);
        return lower.contains("text/html") || lower.contains("application/xhtml") || lower.contains("text/plain");
    }
}

