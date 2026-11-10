package com.webshield.api.search;

import java.io.Serializable;

/**
 * Multi-dimensional fitness evaluation score for an API test candidate with respect to an objective.
 */
public record FitnessScore(
        boolean isAchieved,
        double distance,
        double fitness,
        boolean isExecutionFailure,
        boolean isUnusable,
        int complexity,
        String rationale
) implements Serializable {

    public static FitnessScore achieved(int complexity, String rationale) {
        return new FitnessScore(true, 0.0, 1.0, false, false, complexity, rationale);
    }

    public static FitnessScore progressing(double distance, double fitness, int complexity, String rationale) {
        return new FitnessScore(false, distance, fitness, false, false, complexity, rationale);
    }

    public static FitnessScore executionFailure(String rationale) {
        return new FitnessScore(false, 1.0, 0.0, true, false, Integer.MAX_VALUE, rationale);
    }

    public static FitnessScore unusable(String rationale) {
        return new FitnessScore(false, 1.0, 0.0, false, true, Integer.MAX_VALUE, rationale);
    }

    /**
     * Compares two scores for archive retention.
     * Higher fitness wins. If fitness is equal, lower complexity wins.
     */
    public boolean isBetterThan(FitnessScore other) {
        if (other == null) return true;
        if (this.isAchieved && !other.isAchieved) return true;
        if (!this.isAchieved && other.isAchieved) return false;

        // If fitness differs significantly
        if (Math.abs(this.fitness - other.fitness) > 0.0001) {
            return this.fitness > other.fitness;
        }

        // Tie-breaker: lower test complexity (fewer parameters/smaller payload) is preferred
        return this.complexity < other.complexity;
    }
}

