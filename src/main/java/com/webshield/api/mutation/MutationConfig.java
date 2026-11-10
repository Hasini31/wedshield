package com.webshield.api.mutation;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * Configuration governing the execution, constraints, and limits of the API Input Mutation Engine.
 */
public class MutationConfig {

    private double mutationProbability = 0.8;
    private int maxMutationsPerTestCase = 10;
    private int maxMutationDepth = 3;
    private int maxTotalMutations = 100;
    private long seed = 42L;
    private Set<MutationCategory> enabledCategories = EnumSet.allOf(MutationCategory.class);

    public MutationConfig() {
    }

    public static MutationConfig defaultConfig() {
        return new MutationConfig();
    }

    public static Builder builder() {
        return new Builder();
    }

    public boolean isCategoryEnabled(MutationCategory category) {
        return category != null && enabledCategories.contains(category);
    }

    public double getMutationProbability() {
        return mutationProbability;
    }

    public void setMutationProbability(double mutationProbability) {
        if (mutationProbability < 0.0 || mutationProbability > 1.0) {
            throw new IllegalArgumentException("Mutation probability must be between 0.0 and 1.0");
        }
        this.mutationProbability = mutationProbability;
    }

    public int getMaxMutationsPerTestCase() {
        return maxMutationsPerTestCase;
    }

    public void setMaxMutationsPerTestCase(int maxMutationsPerTestCase) {
        if (maxMutationsPerTestCase < 1) {
            throw new IllegalArgumentException("maxMutationsPerTestCase must be at least 1");
        }
        this.maxMutationsPerTestCase = maxMutationsPerTestCase;
    }

    public int getMaxMutationDepth() {
        return maxMutationDepth;
    }

    public void setMaxMutationDepth(int maxMutationDepth) {
        if (maxMutationDepth < 1) {
            throw new IllegalArgumentException("maxMutationDepth must be at least 1");
        }
        this.maxMutationDepth = maxMutationDepth;
    }

    public int getMaxTotalMutations() {
        return maxTotalMutations;
    }

    public void setMaxTotalMutations(int maxTotalMutations) {
        if (maxTotalMutations < 1) {
            throw new IllegalArgumentException("maxTotalMutations must be at least 1");
        }
        this.maxTotalMutations = maxTotalMutations;
    }

    public long getSeed() {
        return seed;
    }

    public void setSeed(long seed) {
        this.seed = seed;
    }

    public Set<MutationCategory> getEnabledCategories() {
        return Collections.unmodifiableSet(enabledCategories);
    }

    public void setEnabledCategories(Set<MutationCategory> enabledCategories) {
        this.enabledCategories = enabledCategories != null && !enabledCategories.isEmpty()
                ? EnumSet.copyOf(enabledCategories)
                : EnumSet.noneOf(MutationCategory.class);
    }

    public static class Builder {
        private final MutationConfig config = new MutationConfig();

        public Builder mutationProbability(double prob) {
            config.setMutationProbability(prob);
            return this;
        }

        public Builder maxMutationsPerTestCase(int max) {
            config.setMaxMutationsPerTestCase(max);
            return this;
        }

        public Builder maxMutationDepth(int depth) {
            config.setMaxMutationDepth(depth);
            return this;
        }

        public Builder maxTotalMutations(int total) {
            config.setMaxTotalMutations(total);
            return this;
        }

        public Builder seed(long seed) {
            config.setSeed(seed);
            return this;
        }

        public Builder enabledCategories(Set<MutationCategory> categories) {
            config.setEnabledCategories(categories);
            return this;
        }

        public MutationConfig build() {
            return config;
        }
    }
}

