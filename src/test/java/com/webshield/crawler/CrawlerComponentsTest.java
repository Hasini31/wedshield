package com.webshield.crawler;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Crawler Components Tests")
class CrawlerComponentsTest {

    @Nested
    @DisplayName("URLNormalizer Tests")
    class NormalizerTests {

        private final URLNormalizer normalizer = new URLNormalizer();

        @Test
        @DisplayName("Resolves relative URLs against base URL")
        void testRelativeResolution() {
            String base = "https://example.com/section/page.html";
            Optional<String> res1 = normalizer.normalize("/about", base);
            assertTrue(res1.isPresent());
            assertEquals("https://example.com/about", res1.get());

            Optional<String> res2 = normalizer.normalize("../contact", base);
            assertTrue(res2.isPresent());
            assertEquals("https://example.com/contact", res2.get());
        }

        @Test
        @DisplayName("Strips URL hash fragments to prevent duplicate crawling")
        void testStripFragment() {
            String base = "https://example.com";
            Optional<String> res = normalizer.normalize("/page#heading-2", base);
            assertTrue(res.isPresent());
            assertEquals("https://example.com/page", res.get());
        }

        @Test
        @DisplayName("Canonicalizes query parameter ordering")
        void testQueryParameterSorting() {
            String base = "https://example.com";
            Optional<String> res1 = normalizer.normalize("/search?b=2&a=1", base);
            Optional<String> res2 = normalizer.normalize("/search?a=1&b=2", base);

            assertTrue(res1.isPresent());
            assertTrue(res2.isPresent());
            assertEquals(res1.get(), res2.get(), "Normalized URLs with different param order should match");
            assertEquals("https://example.com/search?a=1&b=2", res1.get());
        }

        @Test
        @DisplayName("Filters out non-HTTP schemes like javascript:, mailto:, tel:")
        void testFilterNonHttp() {
            String base = "https://example.com";
            assertTrue(normalizer.normalize("javascript:alert(1)", base).isEmpty());
            assertTrue(normalizer.normalize("mailto:admin@example.com", base).isEmpty());
            assertTrue(normalizer.normalize("tel:+1234567890", base).isEmpty());
            assertTrue(normalizer.normalize("#just-anchor", base).isEmpty());
        }
    }

    @Nested
    @DisplayName("URLDiscovery Scope and Safety Tests")
    class ScopeTests {

        @Test
        @DisplayName("Accepts in-scope domain and subdomains")
        void testInScope() {
            URLDiscovery discovery = new URLDiscovery("example.com", false);
            assertTrue(discovery.isInScope("https://example.com/home"));
            assertTrue(discovery.isInScope("https://sub.example.com/login"));
            assertTrue(discovery.isInScope("https://example.com:8443/products"));

            // Out-of-scope domain
            assertFalse(discovery.isInScope("https://attacker.com/evil"));
            assertFalse(discovery.isInScope("https://google.com"));
        }

        @Test
        @DisplayName("Rejects static media and binary extensions")
        void testStaticMediaExtensions() {
            URLDiscovery discovery = new URLDiscovery("example.com", false);
            assertFalse(discovery.isInScope("https://example.com/logo.png"));
            assertFalse(discovery.isInScope("https://example.com/image.JPG"));
            assertFalse(discovery.isInScope("https://example.com/report.pdf"));
            assertFalse(discovery.isInScope("https://example.com/archive.zip"));
            assertFalse(discovery.isInScope("https://example.com/style.css"));
            assertFalse(discovery.isInScope("https://example.com/font.woff2"));
        }

        @Test
        @DisplayName("SSRF protection blocks localhost and private IP targets when allowLocalhost is false")
        void testSsrfProtection() {
            URLDiscovery discovery = new URLDiscovery("localhost", false);
            assertFalse(discovery.isInScope("http://localhost/admin"), "Should block localhost when allowLocalhost is false");
            assertFalse(discovery.isInScope("http://127.0.0.1:8080/app"), "Should block loopback IP");

            // When allowLocalhost is explicitly true for local dev
            URLDiscovery devDiscovery = new URLDiscovery("localhost", true);
            assertTrue(devDiscovery.isInScope("http://localhost/admin"), "Should allow localhost when explicitly configured");
        }
    }

    @Nested
    @DisplayName("VisitedURLTracker Tests")
    class VisitedTrackerTests {

        @Test
        @DisplayName("Tracks visited and queued URLs without duplication")
        void testTracker() {
            VisitedURLTracker tracker = new VisitedURLTracker();
            String url1 = "https://example.com/page1";
            String url2 = "https://example.com/page2";

            assertTrue(tracker.queueUrl(url1));
            assertFalse(tracker.queueUrl(url1), "Queuing same URL again should return false");

            assertFalse(tracker.isVisited(url1));
            assertTrue(tracker.markVisited(url1));
            assertFalse(tracker.markVisited(url1), "Marking visited again should return false");
            assertTrue(tracker.isVisited(url1));

            assertEquals(1, tracker.getVisitedCount());
            assertEquals(1, tracker.getQueuedCount());

            tracker.clear();
            assertEquals(0, tracker.getVisitedCount());
        }
    }

    @Nested
    @DisplayName("LinkExtractor and FormExtractor Tests")
    class ParserTests {

        private final LinkExtractor linkExtractor = new LinkExtractor();
        private final FormExtractor formExtractor = new FormExtractor();

        @Test
        @DisplayName("Extracts hyperlinks and title from HTML")
        void testLinkExtraction() {
            String html = """
                    <!DOCTYPE html>
                    <html>
                    <head><title>WebShield Test Target</title></head>
                    <body>
                        <a href="/dashboard">Dashboard</a>
                        <a href="https://example.com/settings">Settings</a>
                        <a href="javascript:void(0)">Ignored</a>
                        <iframe src="/embedded/frame"></iframe>
                    </body>
                    </html>
                    """;

            Set<String> links = linkExtractor.extractLinks(html, "https://example.com");
            assertEquals("WebShield Test Target", linkExtractor.extractTitle(html));

            assertTrue(links.contains("https://example.com/dashboard"));
            assertTrue(links.contains("https://example.com/settings"));
            assertTrue(links.contains("https://example.com/embedded/frame"));
            assertFalse(links.contains("javascript:void(0)"));
        }

        @Test
        @DisplayName("Extracts forms, actions, methods, and input fields")
        void testFormExtraction() {
            String html = """
                    <html>
                    <body>
                        <form id="loginForm" name="auth" action="/auth/login" method="POST">
                            <input type="text" name="username" placeholder="Username" required />
                            <input type="password" name="password" maxlength="32" required />
                            <textarea name="comments" maxlength="200"></textarea>
                            <select name="role">
                                <option value="user">User</option>
                            </select>
                            <button type="submit" name="submitBtn">Sign In</button>
                        </form>
                    </body>
                    </html>
                    """;

            List<DiscoveredForm> forms = formExtractor.extractForms(html, "https://example.com/login");
            assertEquals(1, forms.size());

            DiscoveredForm form = forms.get(0);
            assertEquals("POST", form.getFormMethod());
            assertEquals("https://example.com/auth/login", form.getFormAction());
            assertEquals("loginForm", form.getFormId());
            assertEquals("auth", form.getFormName());
            assertEquals(5, form.getFieldCount());

            Optional<DiscoveredField> userField = form.getFields().stream().filter(f -> f.getName().equals("username")).findFirst();
            assertTrue(userField.isPresent());
            assertEquals("text", userField.get().getType());
            assertTrue(userField.get().isRequired());

            Optional<DiscoveredField> passField = form.getFields().stream().filter(f -> f.getName().equals("password")).findFirst();
            assertTrue(passField.isPresent());
            assertEquals("password", passField.get().getType());
            assertTrue(passField.get().isHasMaxlength());
        }
    }

    @Nested
    @DisplayName("ParameterExtractor Tests")
    class ParamExtractorTests {

        private final ParameterExtractor extractor = new ParameterExtractor();

        @Test
        @DisplayName("Extracts and decodes query parameters")
        void testQueryParamExtraction() {
            String url = "https://example.com/search?query=security+scanner&page=2&filter=active";
            Map<String, List<String>> params = extractor.extractQueryParameters(url);

            assertEquals(3, params.size());
            assertEquals(List.of("security scanner"), params.get("query"));
            assertEquals(List.of("2"), params.get("page"));
            assertEquals(List.of("active"), params.get("filter"));
        }

        @Test
        @DisplayName("Returns empty map when URL has no query parameters")
        void testNoQuery() {
            Map<String, List<String>> params = extractor.extractQueryParameters("https://example.com/about");
            assertTrue(params.isEmpty());
        }
    }
}

