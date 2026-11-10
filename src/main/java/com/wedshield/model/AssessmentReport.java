package com.wedshield.model;

import java.util.List;

public record AssessmentReport(
        List<String> openApiMutations,
        List<String> crawledUrls,
        List<Finding> findings,
        RegressionReport regression
) {
}
