package com.wedshield.analysis;

import com.wedshield.model.Finding;
import com.wedshield.model.RegressionReport;
import com.wedshield.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DifferentialRegressionAnalyzerTest {

    @Test
    void identifiesNewAndResolvedFindings() {
        Finding baselineOnly = new Finding("A", "a", Severity.LOW, "d", "/a");
        Finding shared = new Finding("B", "b", Severity.MEDIUM, "d", "/b");
        Finding currentOnly = new Finding("C", "c", Severity.HIGH, "d", "/c");

        RegressionReport report = new DifferentialRegressionAnalyzer().compare(
                List.of(baselineOnly, shared),
                List.of(shared, currentOnly)
        );

        assertEquals(List.of(currentOnly), report.newFindings());
        assertEquals(List.of(baselineOnly), report.resolvedFindings());
    }
}
