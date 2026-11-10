package com.wedshield.model;

import java.util.List;
import java.util.Objects;

public record AssessmentRequest(String targetUrl, String openApiDocument, String crawlHtml, List<Finding> baselineFindings) {
    public AssessmentRequest {
        Objects.requireNonNull(targetUrl, "targetUrl");
    }
}
