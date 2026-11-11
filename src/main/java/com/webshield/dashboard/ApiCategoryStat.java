package com.webshield.dashboard;

/**
 * Statistics for a single API test case category.
 */
public record ApiCategoryStat(
        String category,
        int generatedCount,
        int executedCount,
        int findingsCount
) {}
