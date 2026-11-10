package com.webshield;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.InputStream;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Baseline verification tests confirming that all critical resource
 * files are available on the classpath and are non-empty.
 */
public class AppTest {

    @Test
    @DisplayName("Shell FXML layout resource exists and is non-empty")
    void testShellFxmlExists() {
        assertResourceExists("/fxml/shell.fxml");
    }

    @Test
    @DisplayName("CSS stylesheet resource exists and is non-empty")
    void testCssExists() {
        assertResourceExists("/css/styles.css");
    }

    @Test
    @DisplayName("Logback configuration resource exists")
    void testLogbackConfigExists() {
        URL url = getClass().getResource("/logback.xml");
        assertNotNull(url, "/logback.xml must be available on the classpath");
    }

    @ParameterizedTest(name = "Page FXML exists: {0}")
    @DisplayName("All page FXML layouts exist")
    @ValueSource(strings = {
        "/fxml/pages/login.fxml",
        "/fxml/pages/register.fxml",
        "/fxml/pages/dashboard.fxml",
        "/fxml/pages/websites.fxml",
        "/fxml/pages/website_details.fxml",
        "/fxml/pages/add_website_dialog.fxml",
        "/fxml/pages/security_scans.fxml",
        "/fxml/pages/scan_history.fxml",
        "/fxml/pages/reports.fxml",
        "/fxml/pages/settings.fxml",
        "/fxml/pages/api_projects.fxml",
        "/fxml/pages/import_spec_dialog.fxml",
        "/fxml/pages/api_project_details.fxml",
        "/fxml/pages/api_test_config.fxml",
        "/fxml/pages/api_scan_execution.fxml",
        "/fxml/pages/api_test_cases.fxml",
        "/fxml/pages/api_execution_results.fxml",
        "/fxml/pages/api_security_findings.fxml",
        "/fxml/pages/api_scan_history.fxml",
        "/fxml/pages/api_scan_comparison.fxml",
        "/fxml/pages/api_reports.fxml"
    })
    void testPageFxmlsExist(String path) {
        assertResourceExists(path);
    }

    /* ------------------------------------------------------------------ */

    private void assertResourceExists(String resourcePath) {
        URL url = getClass().getResource(resourcePath);
        assertNotNull(url, "Resource must exist on classpath: " + resourcePath);

        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            assertNotNull(is, "Resource stream must be readable: " + resourcePath);
            assertTrue(is.available() > 0, "Resource must not be empty: " + resourcePath);
        } catch (Exception e) {
            throw new AssertionError("Could not read resource: " + resourcePath, e);
        }
    }
}
