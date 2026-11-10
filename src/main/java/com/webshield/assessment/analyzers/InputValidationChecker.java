package com.webshield.assessment.analyzers;

import com.webshield.assessment.AssessmentContext;
import com.webshield.assessment.AssessmentRule;
import com.webshield.assessment.models.AssessmentResult;
import com.webshield.assessment.models.ConfidenceLevel;
import com.webshield.assessment.models.Severity;
import com.webshield.crawler.DiscoveredField;
import com.webshield.crawler.DiscoveredForm;
import com.webshield.crawler.DiscoveredPage;
import com.webshield.http.HttpResponseData;

import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Evaluates input validation configuration on discovered forms and parameters.
 * Reference: OWASP Input Validation Cheat Sheet.
 */
@Component
public class InputValidationChecker implements AssessmentRule {

    @Override
    public String getRuleId() { return "WS-RULE-INPUT-VALIDATION"; }

    @Override
    public String getName() { return "Input Validation Assessment"; }

    @Override
    public String getCategory() { return "Input Validation"; }

    @Override
    public List<AssessmentResult> analyze(AssessmentContext context, DiscoveredPage page, HttpResponseData response) {
        List<AssessmentResult> results = new ArrayList<>();
        if (page == null || !page.isHasForms()) {
            return results;
        }

        for (DiscoveredForm form : page.getForms()) {
            int requiredCount = 0;
            int clientConstraintCount = 0;
            List<String> unconstrainedFields = new ArrayList<>();

            for (DiscoveredField field : form.getFields()) {
                if (field.getName() == null || field.getName().isEmpty()) continue;
                if ("hidden".equalsIgnoreCase(field.getType()) || "submit".equalsIgnoreCase(field.getType())) continue;

                if (field.isRequired()) {
                    requiredCount++;
                    clientConstraintCount++;
                }
                if (field.isHasMaxlength() || field.isHasPattern()) {
                    clientConstraintCount++;
                } else if (!field.isRequired()) {
                    unconstrainedFields.add(field.getName());
                }
            }

            // Flag forms that have no constraints on inputs
            if (!unconstrainedFields.isEmpty()) {
                results.add(new AssessmentResult(
                        "Missing Server-Side Input Validation Indicators",
                        "Input Validation",
                        "WS-INP-001",
                        form.getFormAction(),
                        String.join(", ", unconstrainedFields),
                        form.getFormMethod(),
                        Severity.INFORMATIONAL,
                        ConfidenceLevel.INFORMATIONAL,
                        "Form fields (" + String.join(", ", unconstrainedFields) + ") in form at '" + form.getFormAction() +
                                "' rely on minimal or absent client-side constraints. Server-side validation, sanitization, and type checking are essential.",
                        "Form action: " + form.getFormAction() + " | Method: " + form.getFormMethod() + " | Unconstrained: " + unconstrainedFields,
                        "Form Schema Inspection",
                        "Implement strict server-side validation against a whitelist for all incoming form parameters, regardless of client-side validation."
                ));
            }
        }

        return results;
    }
}

