package com.webshield.scan;

import com.webshield.database.repositories.ScanRecord;
import com.webshield.database.repositories.ScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import org.springframework.stereotype.Service;

/**
 * Service facade providing scan initiation, progress tracking, and history management.
 */
@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final ScanManager scanManager;
    private final ScanRepository scanRepository;

    public ScanService() {
        this(ScanManager.getInstance(), new ScanRepository());
    }

    public ScanService(ScanManager scanManager, ScanRepository scanRepository) {
        this.scanManager = scanManager;
        this.scanRepository = scanRepository;
    }

    /**
     * Starts an asynchronous security scan with real-time progress callbacks.
     */
    public CompletableFuture<ScanExecutionResult> startScan(ScanConfiguration config, ScanProgressTracker tracker) {
        if (config == null) {
            throw new IllegalArgumentException("ScanConfiguration cannot be null.");
        }
        config.validate();
        return scanManager.submitScan(config, tracker);
    }

    /**
     * Cancels an active scan.
     */
    public boolean cancelScan(long scanId) {
        return scanManager.cancelScan(scanId);
    }

    /**
     * Retrieves the history of scans for an authenticated user.
     */
    public List<ScanRecord> getUserScanHistory(int userId) {
        if (userId <= 0) return Collections.emptyList();
        return scanRepository.findAllByUserId(userId);
    }

    /**
     * Retrieves details for a specific scan.
     */
    public Optional<ScanRecord> getScanDetails(long scanId, int userId) {
        if (scanId <= 0 || userId <= 0) return Optional.empty();
        return scanRepository.findById(scanId, userId);
    }

    /**
     * Deletes a scan record ensuring user ownership isolation.
     */
    public boolean deleteScan(long scanId, int userId) {
        if (scanId <= 0 || userId <= 0) return false;
        return scanRepository.deleteScan(scanId, userId);
    }

    /**
     * Checks if a scan is currently active.
     */
    public boolean isScanActive(long scanId) {
        return scanManager.isScanActive(scanId);
    }
}

