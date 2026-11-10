package com.webshield.assessment.analyzers;

import com.webshield.assessment.AssessmentContext;
import com.webshield.assessment.AssessmentRule;
import com.webshield.assessment.models.AssessmentResult;
import com.webshield.assessment.models.ConfidenceLevel;
import com.webshield.assessment.models.Severity;
import com.webshield.crawler.DiscoveredPage;
import com.webshield.http.HttpCookieData;
import com.webshield.http.HttpResponseData;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

/**
 * Inspects response cookies for missing security attributes (HttpOnly, Secure, SameSite).
 * Reference: OWASP ZAP CookieSecurityScanner.
 */
@Component
public class CookieSecurityChecker implements AssessmentRule {

    @Override
    public String getRuleId() { return "WS-RULE-COOKIES"; }

    @Override
    public String getName() { return "Cookie Security Configuration"; }

    @Override
    public String getCategory() { return "Cookie Security"; }

    @Override
    public List<AssessmentResult> analyze(AssessmentContext context, DiscoveredPage page, HttpResponseData response) {
        List<AssessmentResult> results = new ArrayList<>();
        if (response == null || response.getCookies().isEmpty()) {
            return results;
        }

        String url = page.getUrl();
        boolean isHttps = url.toLowerCase(Locale.ROOT).startsWith("https://");

        for (HttpCookieData cookie : response.getCookies()) {
            String cookieName = cookie.getName();

            // 1. Missing HttpOnly
            if (!cookie.isHttpOnly()) {
                results.add(new AssessmentResult(
                        "Cookie Missing HttpOnly Flag",
                        "Cookie Security",
                        "WS-CKY-001",
                        url,
                        cookieName,
                        page.getHttpMethod(),
                        Severity.MEDIUM,
                        ConfidenceLevel.CONFIRMED,
                        "The cookie '" + cookieName + "' was set without the 'HttpOnly' flag, making it accessible to client-side scripts via document.cookie.",
                        "Cookie: " + cookie,
                        "Cookie Header Analysis",
                        "Add the 'HttpOnly' attribute to all session and sensitive cookies to mitigate XSS cookie theft."
                ));
            }

            // 2. Missing Secure (especially on HTTPS)
            if (!cookie.isSecure() && isHttps) {
                results.add(new AssessmentResult(
                        "Cookie Missing Secure Flag",
                        "Cookie Security",
                        "WS-CKY-002",
                        url,
                        cookieName,
                        page.getHttpMethod(),
                        Severity.MEDIUM,
                        ConfidenceLevel.CONFIRMED,
                        "The cookie '" + cookieName + "' was transmitted over an HTTPS connection without the 'Secure' attribute.",
                        "Cookie: " + cookie,
                        "Cookie Header Analysis",
                        "Ensure the 'Secure' attribute is set on all cookies transmitted over TLS/HTTPS."
                ));
            }

            // 3. Missing SameSite attribute
            if (cookie.getSameSite() == null || cookie.getSameSite().isEmpty()) {
                results.add(new AssessmentResult(
                        "Cookie Missing SameSite Attribute",
                        "Cookie Security",
                        "WS-CKY-003",
                        url,
                        cookieName,
                        page.getHttpMethod(),
                        Severity.LOW,
                        ConfidenceLevel.CONFIRMED,
                        "The cookie '" + cookieName + "' does not define a 'SameSite' attribute (Lax or Strict), increasing exposure to Cross-Site Request Forgery (CSRF).",
                        "Cookie: " + cookie,
                        "Cookie Header Analysis",
                        "Configure 'SameSite=Lax' or 'SameSite=Strict' on cookies to restrict cross-site transmission."
                ));
            }
        }

        return results;
    }
}

