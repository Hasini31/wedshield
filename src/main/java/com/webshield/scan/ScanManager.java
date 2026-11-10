package com.webshield.scan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.*;
import org.springframework.stereotype.Component;

/**
 * Centralized manager coordinating background scan execution, thread pooling,
 * active scan tracking, and cooperative cancellation.
 */
@Component
public class ScanManager {

    private static final Logger log = LoggerFactory.getLogger(ScanManager.class);

    private static volatile ScanManager instance;

    private final ExecutorService executor;
    private final Map<Long, ScanTask> activeScans = new ConcurrentHashMap<>();
    private final Map<Long, Future<ScanExecutionResult>> activeFutures = new ConcurrentHashMap<>();

    public ScanManager() {
        int threads = Math.max(2, Runtime.getRuntime().availableProcessors() / 2);
        ThreadFactory daemonFactory = r -> {
            Thread t = new Thread(r, "webshield-scan-worker");
            t.setDaemon(true);
            return t;
        };
        this.executor = Executors.newFixedThreadPool(threads, daemonFactory);
        instance = this;
        log.info("ScanManager initialized with worker pool of {} threads.", threads);
    }

    public static ScanManager getInstance() {
        if (instance == null) {
            synchronized (ScanManager.class) {
                if (instance == null) {
                    instance = new ScanManager();
                }
            }
        }
        return instance;
    }

    /**
     * Submits a security scan configuration for background asynchronous execution.
     *
     * @param config  Scan configuration parameters
     * @param tracker Real-time progress tracker to bind to
     * @return CompletableFuture completing when the scan finishes
     */
    public CompletableFuture<ScanExecutionResult> submitScan(ScanConfiguration config, ScanProgressTracker tracker) {
        ScanTask task = new ScanTask(config, tracker);

        CompletableFuture<ScanExecutionResult> future = CompletableFuture.supplyAsync(() -> {
            try {
                return task.call();
            } finally {
                if (task.getScanId() > 0) {
                    activeScans.remove(task.getScanId());
                    activeFutures.remove(task.getScanId());
                }
            }
        }, executor);

        // Pre-register with placeholder ID or track once task initializes
        long estimatedKey = config.getWebsiteId() * 100_000L + System.currentTimeMillis() % 100_000L;
        activeScans.put(estimatedKey, task);

        return future;
    }

    /**
     * Directly runs a {@link ScanTask} via executor, registering its ID once created.
     */
    public Future<ScanExecutionResult> submitTask(ScanTask task) {
        Future<ScanExecutionResult> future = executor.submit(task);
        if (task.getScanId() > 0) {
            activeScans.put(task.getScanId(), task);
            activeFutures.put(task.getScanId(), future);
        }
        return future;
    }

    /**
     * Cooperatively cancels an active scan.
     */
    public boolean cancelScan(long scanId) {
        ScanTask task = activeScans.get(scanId);
        if (task != null) {
            log.info("Requesting cancellation for scan id={}", scanId);
            task.cancel();
            Future<?> f = activeFutures.get(scanId);
            if (f != null) {
                f.cancel(true);
            }
            activeScans.remove(scanId);
            activeFutures.remove(scanId);
            return true;
        }

        // Search through active scans if mapped by temporary key
        for (Map.Entry<Long, ScanTask> entry : activeScans.entrySet()) {
            if (entry.getValue().getScanId() == scanId) {
                entry.getValue().cancel();
                activeScans.remove(entry.getKey());
                return true;
            }
        }

        return false;
    }

    /**
     * Cancels all active scans (e.g. on application exit).
     */
    public void cancelAllScans() {
        for (ScanTask task : activeScans.values()) {
            task.cancel();
        }
        activeScans.clear();
        activeFutures.clear();
    }

    /**
     * Checks if a scan ID is actively running.
     */
    public boolean isScanActive(long scanId) {
        ScanTask task = activeScans.get(scanId);
        return task != null && !task.isCancelled();
    }

    /**
     * Returns the active task for inspection if present.
     */
    public ScanTask getActiveScan(long scanId) {
        return activeScans.get(scanId);
    }

    /**
     * Gracefully terminates the worker executor.
     */
    @jakarta.annotation.PreDestroy
    public void shutdown() {
        log.debug("Initiating graceful shutdown of ScanManager worker executor...");
        cancelAllScans();
        executor.shutdown();
        try {
            if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                log.debug("ScanManager executor did not terminate in 2s, forcing immediate shutdown.");
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            log.debug("ScanManager shutdown interrupted, forcing immediate shutdown.");
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}

