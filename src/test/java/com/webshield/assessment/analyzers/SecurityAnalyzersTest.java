package com.webshield.assessment.analyzers;

import com.webshield.assessment.AssessmentContext;
import com.webshield.assessment.models.AssessmentResult;
import com.webshield.assessment.models.ConfidenceLevel;
import com.webshield.assessment.models.Severity;
import com.webshield.crawler.DiscoveredField;
import com.webshield.crawler.DiscoveredForm;
import com.webshield.crawler.DiscoveredPage;
import com.webshield.http.HttpCookieData;
import com.webshield.http.HttpResponseData;
import com.webshield.models.Website;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Security Assessment Rules Tests")
class SecurityAnalyzersTest {

    private AssessmentContext context;
    private Website website;

    @BeforeEach
    void setUp() {
        website = new Website();
        website.setId(1);
        website.setName("Test Target");
        website.setUrl("https://example.com");
        website.setAuthorized(true);

        context = new AssessmentContext(website, null, List.of(), new AtomicBoolean(false));
    }

    @Nested
    @DisplayName("SecurityHeaderChecker Tests")
    class HeaderCheckerTests {

        private final SecurityHeaderChecker checker = new SecurityHeaderChecker();

        @Test
        @DisplayName("Positive: Response missing security headers triggers findings")
        void testMissingSecurityHeaders() {
            DiscoveredPage page = new DiscoveredPage("https://example.com/login", 0);
            HttpResponseData response = new HttpResponseData(
                    "https://example.com/login",
                    200,
                    Map.of("Content-Type", List.of("text/html")),
                    "<html><body>Login Page</body></html>",
                    50,
                    List.of(),
                    null
            );

            List<AssessmentResult> results = checker.analyze(context, page, response);
            assertFalse(results.isEmpty());

            // Should detect: Missing CSP (HIGH), Missing HSTS (HIGH), Missing X-Frame-Options (MEDIUM), Missing X-Content-Type-Options (LOW), Missing Referrer-Policy (LOW)
            assertTrue(results.stream().anyMatch(r -> r.getVulnerabilityCode().equals("WS-HDR-001")), "Should report missing CSP");
            assertTrue(results.stream().anyMatch(r -> r.getVulnerabilityCode().equals("WS-HDR-002")), "Should report missing HSTS");
            assertTrue(results.stream().anyMatch(r -> r.getVulnerabilityCode().equals("WS-HDR-003")), "Should report missing X-Frame-Options");
            assertTrue(results.stream().anyMatch(r -> r.getVulnerabilityCode().equals("WS-HDR-004")), "Should report missing X-Content-Type-Options");
            assertTrue(results.stream().anyMatch(r -> r.getVulnerabilityCode().equals("WS-HDR-005")), "Should report missing Referrer-Policy");
        }

        @Test
        @DisplayName("Negative: Response with all required security headers triggers zero findings")
        void testAllSecurityHeadersPresent() {
            DiscoveredPage page = new DiscoveredPage("https://example.com/secure", 0);
            HttpResponseData response = new HttpResponseData(
                    "https://example.com/secure",
                    200,
                    Map.of(
                            "Content-Type", List.of("text/html"),
                            "Content-Security-Policy", List.of("default-src 'self'"),
                            "Strict-Transport-Security", List.of("max-age=31536000; includeSubDomains"),
                            "X-Frame-Options", List.of("DENY"),
                            "X-Content-Type-Options", List.of("nosniff"),
                            "Referrer-Policy", List.of("strict-origin-when-cross-origin")
                    ),
                    "<html><body>Secure Page</body></html>",
                    50,
                    List.of(),
                    null
            );

            List<AssessmentResult> results = checker.analyze(context, page, response);
            assertTrue(results.isEmpty(), "Zero findings should be reported when all security headers are properly set");
        }
    }

    @Nested
    @DisplayName("CookieSecurityChecker Tests")
    class CookieCheckerTests {

        private final CookieSecurityChecker checker = new CookieSecurityChecker();

        @Test
        @DisplayName("Positive: Insecure cookie generates HttpOnly, Secure, and SameSite findings")
        void testInsecureCookie() {
            DiscoveredPage page = new DiscoveredPage("https://example.com/app", 0);
            HttpCookieData cookie = new HttpCookieData("sid", "12345", "example.com", "/", false, false, null, -1);

            HttpResponseData response = new HttpResponseData(
                    "https://example.com/app",
                    200,
                    Map.of(),
                    "",
                    50,
                    List.of(cookie),
                    null
            );

            List<AssessmentResult> results = checker.analyze(context, page, response);
            assertEquals(3, results.size());

            assertTrue(results.stream().anyMatch(r -> r.getVulnerabilityCode().equals("WS-CKY-001")), "Should report missing HttpOnly");
            assertTrue(results.stream().anyMatch(r -> r.getVulnerabilityCode().equals("WS-CKY-002")), "Should report missing Secure");
            assertTrue(results.stream().anyMatch(r -> r.getVulnerabilityCode().equals("WS-CKY-003")), "Should report missing SameSite");
        }

        @Test
        @DisplayName("Negative: Hardened cookie triggers zero findings")
        void testSecureCookie() {
            DiscoveredPage page = new DiscoveredPage("https://example.com/app", 0);
            HttpCookieData cookie = new HttpCookieData("sid", "12345", "example.com", "/", true, true, "STRICT", 3600);

            HttpResponseData response = new HttpResponseData(
                    "https://example.com/app",
                    200,
                    Map.of(),
                    "",
                    50,
                    List.of(cookie),
                    null
            );

            List<AssessmentResult> results = checker.analyze(context, page, response);
            assertTrue(results.isEmpty(), "Zero findings should be generated for hardened cookie");
        }
    }

    @Nested
    @DisplayName("SqlErrorAnalyzer Tests")
    class SqlErrorTests {

        private final SqlErrorAnalyzer analyzer = new SqlErrorAnalyzer();

        @Test
        @DisplayName("Positive: Response containing MySQL syntax error is detected")
        void testDetectMysqlError() {
            DiscoveredPage page = new DiscoveredPage("https://example.com/items?id=1", 0);
            String errorBody = "<html><body>Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</body></html>";

            HttpResponseData response = new HttpResponseData(
                    "https://example.com/items?id=1", 500, Map.of(), errorBody, 60, List.of(), null
            );

            List<AssessmentResult> results = analyzer.analyze(context, page, response);
            assertEquals(1, results.size());

            AssessmentResult res = results.get(0);
            assertEquals("WS-SQL-001", res.getVulnerabilityCode());
            assertEquals(Severity.HIGH, res.getSeverity());
            assertEquals(ConfidenceLevel.CONFIRMED, res.getConfidence());
            assertTrue(res.getEvidence().contains("MySQL"));
        }

        @Test
        @DisplayName("Negative: Generic error without database error signature produces zero findings")
        void testGenericErrorIgnored() {
            DiscoveredPage page = new DiscoveredPage("https://example.com/items?id=1", 0);
            String genericBody = "<html><body>Internal Server Error 500. Please contact support.</body></html>";

            HttpResponseData response = new HttpResponseData(
                    "https://example.com/items?id=1", 500, Map.of(), genericBody, 60, List.of(), null
            );

            List<AssessmentResult> results = analyzer.analyze(context, page, response);
            assertTrue(results.isEmpty(), "Generic 500 error must not trigger false positive SQL injection findings");
        }
    }

    @Nested
    @DisplayName("InputReflectionAnalyzer Tests")
    class ReflectionTests {

        private final InputReflectionAnalyzer analyzer = new InputReflectionAnalyzer();

        @Test
        @DisplayName("Positive: Query parameter value reflected in response body triggers finding")
        void testReflectedParam() {
            DiscoveredPage page = new DiscoveredPage("https://example.com/search?keyword=testquery", 0);
            String body = "<html><body>Search results for: testquery (0 matches)</body></html>";

            HttpResponseData response = new HttpResponseData(
                    page.getUrl(), 200, Map.of(), body, 40, List.of(), null
            );

            List<AssessmentResult> results = analyzer.analyze(context, page, response);
            assertEquals(1, results.size());

            AssessmentResult ar = results.get(0);
            assertEquals("WS-REF-001", ar.getVulnerabilityCode());
            assertEquals("keyword", ar.getAffectedParam());
        }

        @Test
        @DisplayName("Negative: Non-reflected parameter generates zero findings")
        void testUnreflectedParam() {
            DiscoveredPage page = new DiscoveredPage("https://example.com/search?keyword=unreflectedValue", 0);
            String body = "<html><body>No search results</body></html>";

            HttpResponseData response = new HttpResponseData(
                    page.getUrl(), 200, Map.of(), body, 40, List.of(), null
            );

            List<AssessmentResult> results = analyzer.analyze(context, page, response);
            assertTrue(results.isEmpty());
        }
    }

    @Nested
    @DisplayName("InputValidationChecker Tests")
    class InputValidationTests {

        private final InputValidationChecker checker = new InputValidationChecker();

        @Test
        @DisplayName("Positive: Form with unconstrained fields generates informational finding")
        void testUnconstrainedForm() {
            DiscoveredPage page = new DiscoveredPage("https://example.com/contact", 0);
            DiscoveredForm form = new DiscoveredForm("https://example.com/contact", "POST", "contactForm", "contact");
            form.addField(new DiscoveredField("message", "textarea", null, null, false, false, false));
            page.addForm(form);

            List<AssessmentResult> results = checker.analyze(context, page, null);
            assertEquals(1, results.size());

            AssessmentResult ar = results.get(0);
            assertEquals("WS-INP-001", ar.getVulnerabilityCode());
            assertEquals(Severity.INFORMATIONAL, ar.getSeverity());
        }

        @Test
        @DisplayName("Negative: Page with no forms generates zero findings")
        void testNoForms() {
            DiscoveredPage page = new DiscoveredPage("https://example.com/about", 0);
            List<AssessmentResult> results = checker.analyze(context, page, null);
            assertTrue(results.isEmpty());
        }
    }
}

