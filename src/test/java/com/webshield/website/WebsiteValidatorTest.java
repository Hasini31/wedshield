package com.webshield.website;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("WebsiteValidator Tests")
class WebsiteValidatorTest {

    private WebsiteValidator validator;

    @BeforeEach
    void setUp() {
        validator = new WebsiteValidator();
    }

    @Nested
    @DisplayName("Website Name Validation")
    class NameValidationTests {

        @Test
        @DisplayName("Valid website name passes")
        void testValidName() {
            assertDoesNotThrow(() -> validator.validateName("Production API"));
            assertDoesNotThrow(() -> validator.validateName("Internal Staging"));
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"   ", "\t", "\n"})
        @DisplayName("Blank or empty name throws IllegalArgumentException")
        void testBlankName(String name) {
            assertThrows(IllegalArgumentException.class, () -> validator.validateName(name));
        }

        @Test
        @DisplayName("Name exceeding 120 characters throws IllegalArgumentException")
        void testExcessiveLengthName() {
            String longName = "A".repeat(121);
            assertThrows(IllegalArgumentException.class, () -> validator.validateName(longName));
        }
    }

    @Nested
    @DisplayName("URL Validation & Scheme Enforcement")
    class UrlValidationTests {

        @ParameterizedTest
        @ValueSource(strings = {
            "http://example.com",
            "https://example.com",
            "https://sub.domain.org/path",
            "http://localhost:8080/test",
            "https://127.0.0.1:8443/app"
        })
        @DisplayName("Valid HTTP and HTTPS URLs pass")
        void testValidUrls(String url) {
            assertDoesNotThrow(() -> validator.validateUrl(url));
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {
            "ftp://example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "gopher://example.com",
            "not-a-valid-url",
            "http://",
            "https://"
        })
        @DisplayName("Non-HTTP/HTTPS schemes or invalid formats throw IllegalArgumentException")
        void testInvalidUrls(String url) {
            assertThrows(IllegalArgumentException.class, () -> validator.validateUrl(url));
        }

        @Test
        @DisplayName("URL normalization trims trailing slashes and normalizes lowercase scheme/host")
        void testNormalizeWebsiteUrl() {
            String normalized = validator.normalizeWebsiteUrl("HTTPS://Example.COM:8080/test/");
            assertEquals("https://example.com:8080/test/", normalized);

            String rootNormalized = validator.normalizeWebsiteUrl("HTTP://TARGET.IO");
            assertEquals("http://target.io/", rootNormalized);
        }
    }

    @Nested
    @DisplayName("Authorization Confirmation Validation")
    class AuthorizationTests {

        @Test
        @DisplayName("Explicit authorization passes")
        void testAuthorizedPasses() {
            assertDoesNotThrow(() -> validator.validateAuthorization(true));
        }

        @Test
        @DisplayName("Unconfirmed authorization throws IllegalArgumentException")
        void testUnauthorizedThrows() {
            assertThrows(IllegalArgumentException.class, () -> validator.validateAuthorization(false));
        }
    }
}

