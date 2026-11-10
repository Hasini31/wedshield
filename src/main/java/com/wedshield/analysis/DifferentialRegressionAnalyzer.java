package com.wedshield.analysis;

import com.wedshield.model.Finding;
import com.wedshield.model.RegressionReport;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class DifferentialRegressionAnalyzer {
    public RegressionReport compare(List<Finding> baseline, List<Finding> current) {
        List<Finding> baselineSafe = baseline == null ? List.of() : baseline;
        List<Finding> currentSafe = current == null ? List.of() : current;

        Set<String> baselineIds = baselineSafe.stream().map(this::fingerprint).collect(Collectors.toSet());
        Set<String> currentIds = currentSafe.stream().map(this::fingerprint).collect(Collectors.toSet());

        List<Finding> newFindings = currentSafe.stream()
                .filter(finding -> !baselineIds.contains(fingerprint(finding)))
                .toList();

        List<Finding> resolvedFindings = baselineSafe.stream()
                .filter(finding -> !currentIds.contains(fingerprint(finding)))
                .toList();

        return new RegressionReport(newFindings, resolvedFindings);
    }

    private String fingerprint(Finding finding) {
        return finding.id() + "|" + finding.location();
    }
}
