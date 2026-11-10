package com.webshield.scan;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ScanConfiguration Unit Tests")
class ScanConfigurationTest {

    @Test
    @DisplayName("Valid configuration passes validation")
    void testValidConfiguration() {
        ScanConfiguration config = new ScanConfiguration(1L, "Target App", "https://example.com", 1)
                .setCrawlDepth(3)
                .setMaxPages(50)
                .setTimeoutSeconds(15)
                .setRateLimitDelayMs(100)
                .setCheckHeaders(true)
                .setCheckCookies(true)
                .setCheckReflection(true)
                .setCheckSqlErrors(true)
                .setCheckInputValidation(true);

        assertDoesNotThrow(config::validate);
        assertTrue(config.hasAnyCategorySelected());
        assertEquals("Target App", config.getWebsiteName());
        assertEquals("https://example.com", config.getWebsiteUrl());
        assertEquals(3, config.getCrawlDepth());
        assertEquals(50, config.getMaxPages());
        assertEquals(15, config.getTimeoutSeconds());
        assertEquals(100, config.getRateLimitDelayMs());
    }

    @Test
    @DisplayName("Invalid websiteId throws IllegalArgumentException")
    void testInvalidWebsiteId() {
        ScanConfiguration config = new ScanConfiguration(0L, "App", "https://example.com", 1);
        assertThrows(IllegalArgumentException.class, config::validate);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   "})
    @DisplayName("Blank target URL throws IllegalArgumentException")
    void testBlankUrl(String url) {
        ScanConfiguration config = new ScanConfiguration(1L, "App", url, 1);
        assertThrows(IllegalArgumentException.class, config::validate);
    }

    @Test
    @DisplayName("Invalid userId throws IllegalArgumentException")
    void testInvalidUserId() {
        ScanConfiguration config = new ScanConfiguration(1L, "App", "https://example.com", 0);
        assertThrows(IllegalArgumentException.class, config::validate);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, 11, 20})
    @DisplayName("Invalid crawl depths throw IllegalArgumentException")
    void testInvalidCrawlDepth(int depth) {
        ScanConfiguration config = new ScanConfiguration(1L, "App", "https://example.com", 1)
                .setCrawlDepth(depth);
        assertThrows(IllegalArgumentException.class, config::validate);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -10, 501, 1000})
    @DisplayName("Invalid max pages throw IllegalArgumentException")
    void testInvalidMaxPages(int max) {
        ScanConfiguration config = new ScanConfiguration(1L, "App", "https://example.com", 1)
                .setMaxPages(max);
        assertThrows(IllegalArgumentException.class, config::validate);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -5, 121, 300})
    @DisplayName("Invalid timeouts throw IllegalArgumentException")
    void testInvalidTimeout(int timeout) {
        ScanConfiguration config = new ScanConfiguration(1L, "App", "https://example.com", 1)
                .setTimeoutSeconds(timeout);
        assertThrows(IllegalArgumentException.class, config::validate);
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 10001})
    @DisplayName("Invalid rate limits throw IllegalArgumentException")
    void testInvalidRateLimit(int delay) {
        ScanConfiguration config = new ScanConfiguration(1L, "App", "https://example.com", 1)
                .setRateLimitDelayMs(delay);
        assertThrows(IllegalArgumentException.class, config::validate);
    }

    @Test
    @DisplayName("Throws IllegalArgumentException when no assessment categories are selected")
    void testNoCategoriesSelected() {
        ScanConfiguration config = new ScanConfiguration(1L, "App", "https://example.com", 1)
                .setCheckHeaders(false)
                .setCheckCookies(false)
                .setCheckReflection(false)
                .setCheckSqlErrors(false)
                .setCheckInputValidation(false);

        assertFalse(config.hasAnyCategorySelected());
        assertThrows(IllegalArgumentException.class, config::validate);
    }
}

