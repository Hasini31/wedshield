package com.webshield;

import com.webshield.auth.AuthService;
import com.webshield.config.SpringContext;
import com.webshield.dashboard.DashboardService;
import com.webshield.findings.FindingService;
import com.webshield.scan.ScanService;
import com.webshield.ui.controllers.LoginController;
import com.webshield.ui.controllers.WebsitesController;
import com.webshield.website.WebsiteService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.test.context.support.DirtiesContextTestExecutionListener;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(properties = {
    "spring.datasource.hikari.initialization-fail-timeout=-1",
    "spring.datasource.hikari.minimum-idle=0",
    "spring.jpa.hibernate.ddl-auto=none"
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@TestExecutionListeners({
    DependencyInjectionTestExecutionListener.class,
    DirtiesContextTestExecutionListener.class
})
class WebShieldApplicationTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private AuthService authService;

    @Autowired
    private WebsiteService websiteService;

    @Autowired
    private ScanService scanService;

    @Autowired
    private FindingService findingService;

    @Autowired
    private DashboardService dashboardService;

    @Autowired
    private com.webshield.http.HttpClientManager httpClientManager;

    @Autowired
    private com.webshield.assessment.SecurityAssessmentEngine securityAssessmentEngine;

    @Autowired
    private com.webshield.api.service.ApiProjectService apiProjectService;

    @Autowired
    private com.webshield.api.parser.OpenApiParser openApiParser;

    @Autowired
    private com.webshield.api.generation.ApiTestGenerator apiTestGenerator;

    @Autowired
    private com.webshield.api.mutation.MutationEngine mutationEngine;

    @Autowired
    private com.webshield.api.search.EvolutionaryTestEngine evolutionaryTestEngine;

    @Autowired
    private com.webshield.api.execution.ApiExecutionEngine apiExecutionEngine;

    @Autowired
    private com.webshield.api.analysis.ApiSecurityAnalyzer apiSecurityAnalyzer;

    @Autowired
    private com.webshield.api.service.ApiPersistenceService apiPersistenceService;

    @Autowired
    private com.webshield.api.reporting.ApiReportService apiReportService;

    @Autowired
    private com.webshield.api.llm.LlmService llmService;

    @Autowired
    private com.webshield.database.DatabaseMigrationService databaseMigrationService;

    @Test
    @DisplayName("Verify Spring Boot ApplicationContext, Service Beans and Controller Wiring")
    void testSpringContextAndBeans() {
        assertNotNull(applicationContext, "ApplicationContext should be loaded");
        assertNotNull(authService, "AuthService bean should be present");
        assertNotNull(websiteService, "WebsiteService bean should be present");
        assertNotNull(scanService, "ScanService bean should be present");
        assertNotNull(findingService, "FindingService bean should be present");
        assertNotNull(dashboardService, "DashboardService bean should be present");
        assertNotNull(httpClientManager, "HttpClientManager bean should be present");
        assertNotNull(securityAssessmentEngine, "SecurityAssessmentEngine bean should be present");
        assertNotNull(apiProjectService, "ApiProjectService bean should be present");
        assertNotNull(openApiParser, "OpenApiParser bean should be present");
        assertNotNull(apiTestGenerator, "ApiTestGenerator bean should be present");
        assertNotNull(mutationEngine, "MutationEngine bean should be present");
        assertNotNull(evolutionaryTestEngine, "EvolutionaryTestEngine bean should be present");
        assertNotNull(apiExecutionEngine, "ApiExecutionEngine bean should be present");
        assertNotNull(apiSecurityAnalyzer, "ApiSecurityAnalyzer bean should be present");
        assertNotNull(apiPersistenceService, "ApiPersistenceService bean should be present");
        assertNotNull(apiReportService, "ApiReportService bean should be present");
        assertNotNull(llmService, "LlmService bean should be present");
        assertNotNull(databaseMigrationService, "DatabaseMigrationService bean should be present");

        // Verify prototype controllers can be created via Spring ApplicationContext
        LoginController loginController = applicationContext.getBean(LoginController.class);
        assertNotNull(loginController, "LoginController bean should be instantiated by Spring");

        WebsitesController websitesController = applicationContext.getBean(WebsitesController.class);
        assertNotNull(websitesController, "WebsitesController bean should be instantiated by Spring");

        com.webshield.ui.controllers.ApiProjectsController apiProjectsController = applicationContext.getBean(com.webshield.ui.controllers.ApiProjectsController.class);
        assertNotNull(apiProjectsController, "ApiProjectsController bean should be instantiated by Spring");

        com.webshield.ui.controllers.ImportSpecDialogController importSpecDialogController = applicationContext.getBean(com.webshield.ui.controllers.ImportSpecDialogController.class);
        assertNotNull(importSpecDialogController, "ImportSpecDialogController bean should be instantiated by Spring");

        assertNotNull(applicationContext.getBean(com.webshield.ui.controllers.ApiProjectDetailsController.class), "ApiProjectDetailsController should be resolvable");
        assertNotNull(applicationContext.getBean(com.webshield.ui.controllers.ApiTestConfigController.class), "ApiTestConfigController should be resolvable");
        assertNotNull(applicationContext.getBean(com.webshield.ui.controllers.ApiScanExecutionController.class), "ApiScanExecutionController should be resolvable");
        assertNotNull(applicationContext.getBean(com.webshield.ui.controllers.ApiTestCasesController.class), "ApiTestCasesController should be resolvable");
        assertNotNull(applicationContext.getBean(com.webshield.ui.controllers.ApiExecutionResultsController.class), "ApiExecutionResultsController should be resolvable");
        assertNotNull(applicationContext.getBean(com.webshield.ui.controllers.ApiSecurityFindingsController.class), "ApiSecurityFindingsController should be resolvable");
        assertNotNull(applicationContext.getBean(com.webshield.ui.controllers.ApiScanHistoryController.class), "ApiScanHistoryController should be resolvable");
        assertNotNull(applicationContext.getBean(com.webshield.ui.controllers.ApiScanComparisonController.class), "ApiScanComparisonController should be resolvable");
        assertNotNull(applicationContext.getBean(com.webshield.ui.controllers.ApiReportsController.class), "ApiReportsController should be resolvable");
    }
}

