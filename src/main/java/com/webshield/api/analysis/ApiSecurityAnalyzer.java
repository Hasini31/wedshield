package com.webshield.api.analysis;

import com.webshield.api.analysis.rules.AuthenticationWeaknessRule;
import com.webshield.api.analysis.rules.AuthorizationWeaknessRule;
import com.webshield.api.analysis.rules.HttpProtocolRule;
import com.webshield.api.analysis.rules.InjectionIndicatorRule;
import com.webshield.api.analysis.rules.InputValidationRule;
import com.webshield.api.analysis.rules.SecurityMisconfigurationRule;
import com.webshield.api.analysis.rules.SensitiveDataExposureRule;
import com.webshield.api.execution.ApiExecutionRequest;
import com.webshield.api.execution.ApiExecutionResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Core orchestration service for rule-based API security response analysis.
 * Manages security rule registration, coordinates rule execution with complete fault isolation,
 * and canonicalizes/deduplicates discovered security findings.
 */
@Service
public class ApiSecurityAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(ApiSecurityAnalyzer.class);

    private final List<ApiSecurityRule> rules = new CopyOnWriteArrayList<>();

    /**
     * Default constructor for standalone programmatic usage, initializing standard built-in rules.
     */
    public ApiSecurityAnalyzer() {
        this(createDefaultRules());
    }

    /**
     * Spring-managed constructor autowiring all discovered ApiSecurityRule beans.
     */
    @Autowired
    public ApiSecurityAnalyzer(List<ApiSecurityRule> discoveredRules) {
        if (discoveredRules != null && !discoveredRules.isEmpty()) {
            this.rules.addAll(discoveredRules);
        } else {
            this.rules.addAll(createDefaultRules());
        }
        log.info("ApiSecurityAnalyzer initialized with {} security rules.", this.rules.size());
    }

    /**
     * Creates standard built-in rule set.
     */
    public static List<ApiSecurityRule> createDefaultRules() {
        return List.of(
                new SensitiveDataExposureRule(),
                new SecurityMisconfigurationRule(),
                new AuthenticationWeaknessRule(),
                new AuthorizationWeaknessRule(),
                new InjectionIndicatorRule(),
                new InputValidationRule(),
                new HttpProtocolRule()
        );
    }

    /**
     * Registers a new custom security rule dynamically.
     */
    public void registerRule(ApiSecurityRule rule) {
        if (rule != null && !rules.contains(rule)) {
            rules.add(rule);
            log.debug("Registered custom security rule: {}", rule.getRuleId());
        }
    }

    /**
     * Returns an unmodifiable view of all registered security rules.
     */
    public List<ApiSecurityRule> getRegisteredRules() {
        return Collections.unmodifiableList(rules);
    }

    /**
     * Analyzes a single HTTP request/response exchange against all registered rules.
     * Guarantees exception isolation: an unhandled exception in one rule will not abort others.
     *
     * @param request outbound HTTP request
     * @param response inbound HTTP response
     * @return deduplicated list of discovered security findings
     */
    public List<ApiSecurityFinding> analyze(ApiExecutionRequest request, ApiExecutionResponse response) {
        if (request == null && response == null) {
            return Collections.emptyList();
        }

        List<ApiSecurityFinding> rawFindings = new ArrayList<>();

        for (ApiSecurityRule rule : rules) {
            try {
                List<ApiSecurityFinding> ruleFindings = rule.analyze(request, response);
                if (ruleFindings != null && !ruleFindings.isEmpty()) {
                    rawFindings.addAll(ruleFindings);
                }
            } catch (Exception ex) {
                log.warn("Security rule '{}' threw an unhandled exception during analysis: {}",
                        rule.getRuleId(), ex.getMessage(), ex);
                // Fault isolation: continue with remaining rules
            }
        }

        return deduplicate(rawFindings);
    }

    /**
     * Analyzes multiple HTTP request/response pairs in batch.
     */
    public List<ApiSecurityFinding> analyzeBatch(List<ApiExchange> exchanges) {
        if (exchanges == null || exchanges.isEmpty()) {
            return Collections.emptyList();
        }

        List<ApiSecurityFinding> combined = new ArrayList<>();
        for (ApiExchange exchange : exchanges) {
            if (exchange != null) {
                combined.addAll(analyze(exchange.request(), exchange.response()));
            }
        }

        return deduplicate(combined);
    }

    /**
     * Canonical deduplication: groups findings by composite signature key and merges duplicates.
     * When identical keys are found, prefers higher severity weight or higher confidence.
     */
    public List<ApiSecurityFinding> deduplicate(List<ApiSecurityFinding> findings) {
        if (findings == null || findings.isEmpty()) {
            return Collections.emptyList();
        }

        Map<String, ApiSecurityFinding> deduplicated = new LinkedHashMap<>();

        for (ApiSecurityFinding finding : findings) {
            if (finding == null) continue;

            String key = finding.getDeduplicationKey();
            if (!deduplicated.containsKey(key)) {
                deduplicated.put(key, finding);
            } else {
                ApiSecurityFinding existing = deduplicated.get(key);
                // Compare severities: keep the one with higher severity or confidence
                if (finding.severity().getWeight() > existing.severity().getWeight()
                        || (finding.severity().getWeight() == existing.severity().getWeight()
                        && finding.confidence().ordinal() < existing.confidence().ordinal())) {
                    deduplicated.put(key, finding);
                }
            }
        }

        return new ArrayList<>(deduplicated.values());
    }

    /**
     * Value record representing a single request/response pair for batch analysis.
     */
    public record ApiExchange(ApiExecutionRequest request, ApiExecutionResponse response) {}
}

