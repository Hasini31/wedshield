package com.webshield.http;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("HTTP Communication Engine Tests")
class HttpEngineTest {

    @Nested
    @DisplayName("HttpRequestBuilder Tests")
    class RequestBuilderTests {

        @Test
        @DisplayName("Builds valid GET request with default headers")
        void testBuildGet() {
            HttpRequestData req = HttpRequestBuilder.get("https://example.com/test")
                    .timeout(20)
                    .build();

            assertEquals("https://example.com/test", req.getUrl());
            assertEquals("GET", req.getMethod());
            assertEquals(20, req.getTimeoutSeconds());
            assertTrue(req.getFirstHeader("User-Agent").isPresent());
            assertTrue(req.getFirstHeader("User-Agent").get().contains("WebShield"));
        }

        @Test
        @DisplayName("Builds valid POST request with body and Content-Type")
        void testBuildPost() {
            HttpRequestData req = HttpRequestBuilder.post("https://example.com/api", "param=val", "application/x-www-form-urlencoded")
                    .build();

            assertEquals("POST", req.getMethod());
            assertEquals("param=val", req.getBody());
            assertEquals("application/x-www-form-urlencoded", req.getFirstHeader("Content-Type").orElse(""));
        }

        @Test
        @DisplayName("Throws IllegalStateException when URL is missing")
        void testMissingUrl() {
            assertThrows(IllegalStateException.class, () -> new HttpRequestBuilder().build());
        }
    }

    @Nested
    @DisplayName("CookieParser Tests")
    class CookieParserTests {

        private final CookieParser parser = new CookieParser();

        @Test
        @DisplayName("Parses standard Set-Cookie directive with security attributes")
        void testParseFullCookie() {
            String raw = "session_token=xyz123456789; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Strict; Max-Age=3600";
            HttpCookieData cookie = parser.parseSingleCookie(raw);

            assertNotNull(cookie);
            assertEquals("session_token", cookie.getName());
            assertEquals("xyz123456789", cookie.getValue());
            assertEquals("example.com", cookie.getDomain());
            assertEquals("/", cookie.getPath());
            assertTrue(cookie.isSecure());
            assertTrue(cookie.isHttpOnly());
            assertEquals("STRICT", cookie.getSameSite());
            assertEquals(3600, cookie.getMaxAge());
        }

        @Test
        @DisplayName("Parses insecure cookie lacking HttpOnly, Secure, and SameSite")
        void testInsecureCookie() {
            String raw = "tracker_id=abc999; Path=/";
            HttpCookieData cookie = parser.parseSingleCookie(raw);

            assertNotNull(cookie);
            assertEquals("tracker_id", cookie.getName());
            assertEquals("abc999", cookie.getValue());
            assertFalse(cookie.isSecure());
            assertFalse(cookie.isHttpOnly());
            assertNull(cookie.getSameSite());
        }

        @Test
        @DisplayName("Handles empty or null cookie strings gracefully")
        void testNullCookie() {
            assertNull(parser.parseSingleCookie(null));
            assertNull(parser.parseSingleCookie("   "));
            assertNull(parser.parseSingleCookie("no_equal_sign"));
        }
    }

    @Nested
    @DisplayName("RedirectHandler Tests")
    class RedirectHandlerTests {

        private final RedirectHandler redirectHandler = new RedirectHandler();

        @Test
        @DisplayName("Resolves valid in-scope redirect to next destination")
        void testValidRedirect() {
            HttpResponseData response = new HttpResponseData(
                    "https://example.com/old",
                    302,
                    Map.of("Location", List.of("/new-location")),
                    "",
                    100,
                    List.of(),
                    null
            );

            Optional<String> nextUrl = redirectHandler.resolveRedirect("https://example.com/old", response, "example.com");
            assertTrue(nextUrl.isPresent());
            assertEquals("https://example.com/new-location", nextUrl.get());
        }

        @Test
        @DisplayName("Blocks out-of-scope redirect destination")
        void testOutOfScopeRedirectBlocked() {
            HttpResponseData response = new HttpResponseData(
                    "https://example.com/redirect",
                    302,
                    Map.of("Location", List.of("https://attacker.com/evil")),
                    "",
                    100,
                    List.of(),
                    null
            );

            Optional<String> nextUrl = redirectHandler.resolveRedirect("https://example.com/redirect", response, "example.com");
            assertTrue(nextUrl.isEmpty(), "Redirect to out-of-scope domain must be blocked");
        }

        @Test
        @DisplayName("Blocks redirect to non-HTTP/HTTPS schemes")
        void testNonHttpRedirectBlocked() {
            HttpResponseData response = new HttpResponseData(
                    "https://example.com/redirect",
                    301,
                    Map.of("Location", List.of("javascript:alert(1)")),
                    "",
                    100,
                    List.of(),
                    null
            );

            Optional<String> nextUrl = redirectHandler.resolveRedirect("https://example.com/redirect", response, "example.com");
            assertTrue(nextUrl.isEmpty(), "Redirect to javascript: scheme must be blocked");
        }
    }

    @Nested
    @DisplayName("HttpHeaderAnalyzer Tests")
    class HeaderAnalyzerTests {

        private final HttpHeaderAnalyzer analyzer = new HttpHeaderAnalyzer();

        @Test
        @DisplayName("Identifies HTML content type responses")
        void testHtmlDetection() {
            HttpResponseData resHtml = new HttpResponseData(
                    "https://example.com", 200, Map.of("Content-Type", List.of("text/html; charset=UTF-8")),
                    "<html></html>", 50, List.of(), null
            );
            assertTrue(analyzer.isHtmlResponse(resHtml));

            HttpResponseData resJson = new HttpResponseData(
                    "https://example.com", 200, Map.of("Content-Type", List.of("application/json")),
                    "{}", 50, List.of(), null
            );
            assertFalse(analyzer.isHtmlResponse(resJson));
        }

        @Test
        @DisplayName("Evaluates HTTPS protocol from URL string")
        void testHttpsCheck() {
            assertTrue(analyzer.isHttps("https://example.com/test"));
            assertFalse(analyzer.isHttps("http://example.com/test"));
        }
    }
}

