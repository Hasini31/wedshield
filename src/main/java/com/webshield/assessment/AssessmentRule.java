package com.webshield.assessment;

import com.webshield.assessment.models.AssessmentResult;
import com.webshield.crawler.DiscoveredPage;
import com.webshield.http.HttpResponseData;

import java.util.List;

/**
 * Strategy interface for modular, independent security assessment rules.
 * Modeled after OWASP ZAP's passive and active scanner abstractions.
 */
public interface AssessmentRule {

    /**
     * Unique identifier for the rule (e.g. "WS-RULE-HEADERS").
     */
    String getRuleId();

    /**
     * Human-readable rule title.
     */
    String getName();

    /**
     * Category of the rule (e.g. "Security Headers", "Cookie Security", "Injection").
     */
    String getCategory();

    /**
     * Analyzes a previously fetched HTTP response (passive analysis).
     */
    List<AssessmentResult> analyze(AssessmentContext context, DiscoveredPage page, HttpResponseData response);

    /**
     * Optional active test probe executed against parameters/forms of the page.
     */
    default List<AssessmentResult> probe(AssessmentContext context, DiscoveredPage page) {
        return List.of();
    }
}

