package com.webshield.api.execution;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * High-precision token-bucket rate limiter enforcing requests-per-second constraints.
 */
public class RateLimiter {

    private final double requestsPerSecond;
    private final long intervalNanos;
    private final ReentrantLock lock = new ReentrantLock();
    private long nextFreeTicketNanos;

    public RateLimiter(double requestsPerSecond) {
        this.requestsPerSecond = Math.max(0.1, requestsPerSecond);
        this.intervalNanos = (long) (1_000_000_000.0 / this.requestsPerSecond);
        this.nextFreeTicketNanos = System.nanoTime();
    }

    /**
     * Blocks until a rate-limiting ticket is available.
     *
     * @throws InterruptedException if interrupted while waiting.
     */
    public void acquire() throws InterruptedException {
        long waitNanos;
        lock.lock();
        try {
            long now = System.nanoTime();
            if (nextFreeTicketNanos <= now) {
                nextFreeTicketNanos = now + intervalNanos;
                return;
            }
            waitNanos = nextFreeTicketNanos - now;
            nextFreeTicketNanos += intervalNanos;
        } finally {
            lock.unlock();
        }

        if (waitNanos > 0) {
            TimeUnit.NANOSECONDS.sleep(waitNanos);
        }
    }

    public double getRequestsPerSecond() {
        return requestsPerSecond;
    }
}

