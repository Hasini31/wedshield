package com.webshield.api.generation;

/**
 * Configuration governing automated rule-based API test-case generation.
 */
public class GenerationConfig {

    private boolean enableValid = true;
    private boolean enableInvalid = true;
    private boolean enableBoundary = true;
    private int maxTestCasesPerEndpoint = 20;
    private int maxNestedDepth = 5;
    private int maxArrayElements = 3;
    private long seed = 1337L;
    private double optionalFieldProbability = 0.5;
    private int maxTotalGeneratedCases = 500;

    public GenerationConfig() {
    }

    public static GenerationConfig defaultConfig() {
        return new GenerationConfig();
    }

    public static Builder builder() {
        return new Builder();
    }

    public void validate() {
        if (maxTestCasesPerEndpoint <= 0) {
            throw new IllegalArgumentException("maxTestCasesPerEndpoint must be greater than 0");
        }
        if (maxNestedDepth <= 0) {
            throw new IllegalArgumentException("maxNestedDepth must be greater than 0");
        }
        if (maxArrayElements <= 0) {
            throw new IllegalArgumentException("maxArrayElements must be greater than 0");
        }
        if (optionalFieldProbability < 0.0 || optionalFieldProbability > 1.0) {
            throw new IllegalArgumentException("optionalFieldProbability must be between 0.0 and 1.0");
        }
        if (maxTotalGeneratedCases <= 0) {
            throw new IllegalArgumentException("maxTotalGeneratedCases must be greater than 0");
        }
    }

    // Getters and Setters
    public boolean isEnableValid() { return enableValid; }
    public void setEnableValid(boolean enableValid) { this.enableValid = enableValid; }

    public boolean isEnableInvalid() { return enableInvalid; }
    public void setEnableInvalid(boolean enableInvalid) { this.enableInvalid = enableInvalid; }

    public boolean isEnableBoundary() { return enableBoundary; }
    public void setEnableBoundary(boolean enableBoundary) { this.enableBoundary = enableBoundary; }

    public int getMaxTestCasesPerEndpoint() { return maxTestCasesPerEndpoint; }
    public void setMaxTestCasesPerEndpoint(int maxTestCasesPerEndpoint) { this.maxTestCasesPerEndpoint = maxTestCasesPerEndpoint; }

    public int getMaxNestedDepth() { return maxNestedDepth; }
    public void setMaxNestedDepth(int maxNestedDepth) { this.maxNestedDepth = maxNestedDepth; }

    public int getMaxArrayElements() { return maxArrayElements; }
    public void setMaxArrayElements(int maxArrayElements) { this.maxArrayElements = maxArrayElements; }

    public long getSeed() { return seed; }
    public void setSeed(long seed) { this.seed = seed; }

    public double getOptionalFieldProbability() { return optionalFieldProbability; }
    public void setOptionalFieldProbability(double optionalFieldProbability) { this.optionalFieldProbability = optionalFieldProbability; }

    public int getMaxTotalGeneratedCases() { return maxTotalGeneratedCases; }
    public void setMaxTotalGeneratedCases(int maxTotalGeneratedCases) { this.maxTotalGeneratedCases = maxTotalGeneratedCases; }

    public static class Builder {
        private final GenerationConfig config = new GenerationConfig();

        public Builder enableValid(boolean enable) { config.setEnableValid(enable); return this; }
        public Builder enableInvalid(boolean enable) { config.setEnableInvalid(enable); return this; }
        public Builder enableBoundary(boolean enable) { config.setEnableBoundary(enable); return this; }
        public Builder maxTestCasesPerEndpoint(int max) { config.setMaxTestCasesPerEndpoint(max); return this; }
        public Builder maxNestedDepth(int depth) { config.setMaxNestedDepth(depth); return this; }
        public Builder maxArrayElements(int elements) { config.setMaxArrayElements(elements); return this; }
        public Builder seed(long seed) { config.setSeed(seed); return this; }
        public Builder optionalFieldProbability(double prob) { config.setOptionalFieldProbability(prob); return this; }
        public Builder maxTotalGeneratedCases(int maxTotal) { config.setMaxTotalGeneratedCases(maxTotal); return this; }

        public GenerationConfig build() {
            config.validate();
            return config;
        }
    }
}

