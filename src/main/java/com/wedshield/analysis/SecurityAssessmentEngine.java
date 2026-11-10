package com.wedshield.analysis;

import com.wedshield.crawl.DynamicCrawler;
import com.wedshield.fuzz.OpenApiMutationFuzzer;
import com.wedshield.model.AssessmentReport;
import com.wedshield.model.AssessmentRequest;
import com.wedshield.model.Finding;
import com.wedshield.owasp.OwaspVulnerabilityDetector;

import java.util.List;

public class SecurityAssessmentEngine {
    private final OpenApiMutationFuzzer mutationFuzzer = new OpenApiMutationFuzzer();
    private final DynamicCrawler crawler = new DynamicCrawler();
    private final OwaspVulnerabilityDetector detector = new OwaspVulnerabilityDetector();
    private final DifferentialRegressionAnalyzer regressionAnalyzer = new DifferentialRegressionAnalyzer();

    public AssessmentReport assess(AssessmentRequest request) {
        List<String> mutations = mutationFuzzer.generateMutations(request.openApiDocument());
        List<String> crawledUrls = crawler.crawl(request.targetUrl(), request.crawlHtml());
        List<Finding> findings = detector.detect(request.targetUrl(), request.crawlHtml(), mutations);

        return new AssessmentReport(
                mutations,
                crawledUrls,
                findings,
                regressionAnalyzer.compare(request.baselineFindings(), findings)
        );
    }
}
