package com.webshield.scan;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Thread-safe tracker for real-time security assessment scan metrics.
 */
public class ScanProgressTracker {

    @FunctionalInterface
    public interface ProgressUpdateListener {
        void onProgressUpdate(ScanProgressTracker tracker);
    }

    private final AtomicInteger pagesDiscovered = new AtomicInteger(0);
    private final AtomicInteger pagesTested = new AtomicInteger(0);
    private final AtomicInteger checksCompleted = new AtomicInteger(0);
    private final AtomicInteger findingsGenerated = new AtomicInteger(0);

    private final AtomicReference<ScanStatus> status = new AtomicReference<>(ScanStatus.PENDING);
    private final AtomicReference<String> currentOperation = new AtomicReference<>("Ready");
    private final AtomicReference<Instant> startTime = new AtomicReference<>(null);
    private final AtomicReference<Instant> completionTime = new AtomicReference<>(null);

    private final List<ProgressUpdateListener> listeners = new CopyOnWriteArrayList<>();

    public ScanProgressTracker() {}

    public void addListener(ProgressUpdateListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(ProgressUpdateListener listener) {
        listeners.remove(listener);
    }

    private void notifyListeners() {
        for (ProgressUpdateListener listener : listeners) {
            try {
                listener.onProgressUpdate(this);
            } catch (Exception ignored) {}
        }
    }

    public void start() {
        this.startTime.set(Instant.now());
        this.status.set(ScanStatus.INITIALIZING);
        this.currentOperation.set("Initializing security scan...");
        notifyListeners();
    }

    public void setStatus(ScanStatus newStatus) {
        this.status.set(newStatus);
        if (newStatus.isTerminal() && completionTime.get() == null) {
            completionTime.set(Instant.now());
        }
        notifyListeners();
    }

    public void setOperation(String operation) {
        this.currentOperation.set(operation != null ? operation : "");
        notifyListeners();
    }

    public void setPagesDiscovered(int count) {
        this.pagesDiscovered.set(Math.max(0, count));
        notifyListeners();
    }

    public void incrementPagesDiscovered() {
        this.pagesDiscovered.incrementAndGet();
        notifyListeners();
    }

    public void addPagesDiscovered(int delta) {
        if (delta > 0) {
            this.pagesDiscovered.addAndGet(delta);
            notifyListeners();
        }
    }

    public void setPagesTested(int count) {
        this.pagesTested.set(Math.max(0, count));
        notifyListeners();
    }

    public void incrementPagesTested() {
        this.pagesTested.incrementAndGet();
        notifyListeners();
    }

    public void incrementChecksCompleted(int count) {
        if (count > 0) {
            this.checksCompleted.addAndGet(count);
            notifyListeners();
        }
    }

    public void setFindingsGenerated(int count) {
        this.findingsGenerated.set(Math.max(0, count));
        notifyListeners();
    }

    public void incrementFindingsGenerated() {
        this.findingsGenerated.incrementAndGet();
        notifyListeners();
    }

    public void addFindingsGenerated(int count) {
        if (count > 0) {
            this.findingsGenerated.addAndGet(count);
            notifyListeners();
        }
    }

    public int getPagesDiscovered() {
        return pagesDiscovered.get();
    }

    public int getPagesTested() {
        return pagesTested.get();
    }

    public int getPagesRemaining() {
        int disc = pagesDiscovered.get();
        int tested = pagesTested.get();
        return Math.max(0, disc - tested);
    }

    public int getChecksCompleted() {
        return checksCompleted.get();
    }

    public int getFindingsGenerated() {
        return findingsGenerated.get();
    }

    public ScanStatus getStatus() {
        return status.get();
    }

    public String getCurrentOperation() {
        return currentOperation.get();
    }

    public Instant getStartTime() {
        return startTime.get();
    }

    public Instant getCompletionTime() {
        return completionTime.get();
    }

    public Duration getElapsedTime() {
        Instant start = startTime.get();
        if (start == null) return Duration.ZERO;
        Instant end = completionTime.get();
        if (end == null) end = Instant.now();
        return Duration.between(start, end);
    }

    public double getProgressPercentage() {
        int total = pagesDiscovered.get();
        if (total <= 0) return 0.0;
        int tested = pagesTested.get();
        double pct = (double) tested / total;
        return Math.min(1.0, Math.max(0.0, pct));
    }

    public void reset() {
        pagesDiscovered.set(0);
        pagesTested.set(0);
        checksCompleted.set(0);
        findingsGenerated.set(0);
        status.set(ScanStatus.PENDING);
        currentOperation.set("Ready");
        startTime.set(null);
        completionTime.set(null);
        notifyListeners();
    }
}

