package com.wedshield.model;

import java.util.List;

public record RegressionReport(List<Finding> newFindings, List<Finding> resolvedFindings) {
}
