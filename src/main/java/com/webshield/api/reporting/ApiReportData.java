package com.webshield.api.reporting;

import com.webshield.api.dto.ApiExecutionDto;
import com.webshield.api.dto.ApiFindingDto;
import com.webshield.api.dto.ApiScanDto;
import com.webshield.api.dto.ApiScanStatisticsDto;
import com.webshield.api.llm.LlmFindingExplanation;
import com.webshield.api.models.ApiProject;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Aggregated data payload passed to report generators containing persisted scan data,
 * project metadata, vulnerability findings, execution statistics, and optional AI explanations.
 */
public record ApiReportData(
        String reportIdentifier,
        String targetApplication,
        String scanName,
        LocalDateTime generatedAt,
        ApiScanDto scan,
        ApiProject project,
        List<ApiFindingDto> findings,
        Optional<ApiScanStatisticsDto> statistics,
        List<ApiExecutionDto> sampleExecutions,
        Map<Long, LlmFindingExplanation> aiExplanations
) implements Serializable {

    public ApiReportData {
        reportIdentifier = (reportIdentifier != null && !reportIdentifier.isBlank())
                ? reportIdentifier : "WS-REP-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        targetApplication = (targetApplication != null && !targetApplication.isBlank()) ? targetApplication : "API Target";
        scanName = (scanName != null && !scanName.isBlank()) ? scanName : "API Security Scan";
        generatedAt = generatedAt != null ? generatedAt : LocalDateTime.now();
        findings = findings != null ? List.copyOf(findings) : List.of();
        sampleExecutions = sampleExecutions != null ? List.copyOf(sampleExecutions) : List.of();
        aiExplanations = aiExplanations != null ? Map.copyOf(aiExplanations) : Map.of();
        statistics = statistics != null ? statistics : Optional.empty();
    }

    public int getCriticalCount() {
        return (int) findings.stream().filter(f -> "CRITICAL".equalsIgnoreCase(f.severity())).count();
    }

    public int getHighCount() {
        return (int) findings.stream().filter(f -> "HIGH".equalsIgnoreCase(f.severity())).count();
    }

    public int getMediumCount() {
        return (int) findings.stream().filter(f -> "MEDIUM".equalsIgnoreCase(f.severity())).count();
    }

    public int getLowCount() {
        return (int) findings.stream().filter(f -> "LOW".equalsIgnoreCase(f.severity())).count();
    }

    public int getInfoCount() {
        return (int) findings.stream().filter(f -> "INFORMATIONAL".equalsIgnoreCase(f.severity()) || "INFO".equalsIgnoreCase(f.severity())).count();
    }

    public Map<String, Integer> getOwaspCategoryCounts() {
        Map<String, Integer> map = new TreeMap<>();
        for (ApiFindingDto f : findings) {
            String cat = f.owaspCategory() != null && !f.owaspCategory().isBlank() ? f.owaspCategory() : "API Security General";
            map.put(cat, map.getOrDefault(cat, 0) + 1);
        }
        return map;
    }

    public Map<String, Integer> getCweCounts() {
        Map<String, Integer> map = new TreeMap<>();
        for (ApiFindingDto f : findings) {
            String cwe = f.cweId() != null && !f.cweId().isBlank() ? f.cweId() : "CWE-General";
            map.put(cwe, map.getOrDefault(cwe, 0) + 1);
        }
        return map;
    }
}

