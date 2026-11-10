package com.webshield.api.search;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe live progress tracker and cancellation controller for evolutionary test search.
 */
public class SearchProgress {

    private final int evaluationBudget;
    private final int maxGenerations;
    private final AtomicInteger currentGeneration = new AtomicInteger(0);
    private final AtomicInteger evaluationsCompleted = new AtomicInteger(0);
    private final AtomicInteger objectivesAchieved = new AtomicInteger(0);
    private final AtomicBoolean cancellationRequested = new AtomicBoolean(false);
    private volatile double currentCoverage = 0.0;
    private volatile SearchStatus status = SearchStatus.NOT_STARTED;

    public SearchProgress(int evaluationBudget, int maxGenerations) {
        this.evaluationBudget = Math.max(1, evaluationBudget);
        this.maxGenerations = Math.max(1, maxGenerations);
    }

    public void cancel() {
        cancellationRequested.set(true);
        this.status = SearchStatus.CANCELLED;
    }

    public boolean isCancelled() {
        return cancellationRequested.get();
    }

    public int incrementGeneration() {
        return currentGeneration.incrementAndGet();
    }

    public int incrementEvaluations() {
        return evaluationsCompleted.incrementAndGet();
    }

    public void updateProgress(int achieved, double coverage) {
        this.objectivesAchieved.set(achieved);
        this.currentCoverage = coverage;
    }

    public double getProgressPercentage() {
        double evalRatio = (double) evaluationsCompleted.get() / evaluationBudget;
        double genRatio = (double) currentGeneration.get() / maxGenerations;
        return Math.min(100.0, Math.max(evalRatio, genRatio) * 100.0);
    }

    // Getters and Setters
    public int getCurrentGeneration() {
        return currentGeneration.get();
    }

    public int getEvaluationsCompleted() {
        return evaluationsCompleted.get();
    }

    public int getEvaluationBudget() {
        return evaluationBudget;
    }

    public int getMaxGenerations() {
        return maxGenerations;
    }

    public int getObjectivesAchieved() {
        return objectivesAchieved.get();
    }

    public double getCurrentCoverage() {
        return currentCoverage;
    }

    public SearchStatus getStatus() {
        return status;
    }

    public void setStatus(SearchStatus status) {
        this.status = status;
    }
}

