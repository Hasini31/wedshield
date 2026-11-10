package com.webshield.api.search;

import java.io.Serializable;

/**
 * Configuration parameters governing the Many Independent Objective (MIO)-inspired
 * evolutionary API test search algorithm.
 */
public class SearchConfiguration implements Serializable {

    private int populationSize = 20;
    private int maxGenerations = 50;
    private double mutationProbability = 0.8;
    private double randomSamplingProbability = 0.2;
    private int evaluationBudget = 200;
    private int maxArchiveSizePerObjective = 3;
    private long seed = 42L;
    private double targetObjectiveCoverage = 1.0;

    public SearchConfiguration() {
    }

    public static SearchConfiguration defaultConfig() {
        return new SearchConfiguration();
    }

    public static Builder builder() {
        return new Builder();
    }

    // Getters and Setters with validation
    public int getPopulationSize() {
        return populationSize;
    }

    public void setPopulationSize(int populationSize) {
        if (populationSize < 1) {
            throw new IllegalArgumentException("populationSize must be at least 1");
        }
        this.populationSize = populationSize;
    }

    public int getMaxGenerations() {
        return maxGenerations;
    }

    public void setMaxGenerations(int maxGenerations) {
        if (maxGenerations < 1) {
            throw new IllegalArgumentException("maxGenerations must be at least 1");
        }
        this.maxGenerations = maxGenerations;
    }

    public double getMutationProbability() {
        return mutationProbability;
    }

    public void setMutationProbability(double mutationProbability) {
        if (mutationProbability < 0.0 || mutationProbability > 1.0) {
            throw new IllegalArgumentException("mutationProbability must be between 0.0 and 1.0");
        }
        this.mutationProbability = mutationProbability;
    }

    public double getRandomSamplingProbability() {
        return randomSamplingProbability;
    }

    public void setRandomSamplingProbability(double randomSamplingProbability) {
        if (randomSamplingProbability < 0.0 || randomSamplingProbability > 1.0) {
            throw new IllegalArgumentException("randomSamplingProbability must be between 0.0 and 1.0");
        }
        this.randomSamplingProbability = randomSamplingProbability;
    }

    public int getEvaluationBudget() {
        return evaluationBudget;
    }

    public void setEvaluationBudget(int evaluationBudget) {
        if (evaluationBudget < 1) {
            throw new IllegalArgumentException("evaluationBudget must be at least 1");
        }
        this.evaluationBudget = evaluationBudget;
    }

    public int getMaxArchiveSizePerObjective() {
        return maxArchiveSizePerObjective;
    }

    public void setMaxArchiveSizePerObjective(int maxArchiveSizePerObjective) {
        if (maxArchiveSizePerObjective < 1) {
            throw new IllegalArgumentException("maxArchiveSizePerObjective must be at least 1");
        }
        this.maxArchiveSizePerObjective = maxArchiveSizePerObjective;
    }

    public long getSeed() {
        return seed;
    }

    public void setSeed(long seed) {
        this.seed = seed;
    }

    public double getTargetObjectiveCoverage() {
        return targetObjectiveCoverage;
    }

    public void setTargetObjectiveCoverage(double targetObjectiveCoverage) {
        if (targetObjectiveCoverage <= 0.0 || targetObjectiveCoverage > 1.0) {
            throw new IllegalArgumentException("targetObjectiveCoverage must be > 0.0 and <= 1.0");
        }
        this.targetObjectiveCoverage = targetObjectiveCoverage;
    }

    public static class Builder {
        private final SearchConfiguration config = new SearchConfiguration();

        public Builder populationSize(int size) {
            config.setPopulationSize(size);
            return this;
        }

        public Builder maxGenerations(int gens) {
            config.setMaxGenerations(gens);
            return this;
        }

        public Builder mutationProbability(double prob) {
            config.setMutationProbability(prob);
            return this;
        }

        public Builder randomSamplingProbability(double prob) {
            config.setRandomSamplingProbability(prob);
            return this;
        }

        public Builder evaluationBudget(int budget) {
            config.setEvaluationBudget(budget);
            return this;
        }

        public Builder maxArchiveSizePerObjective(int max) {
            config.setMaxArchiveSizePerObjective(max);
            return this;
        }

        public Builder seed(long seed) {
            config.setSeed(seed);
            return this;
        }

        public Builder targetObjectiveCoverage(double coverage) {
            config.setTargetObjectiveCoverage(coverage);
            return this;
        }

        public SearchConfiguration build() {
            return config;
        }
    }
}

