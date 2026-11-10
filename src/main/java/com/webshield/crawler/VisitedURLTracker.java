package com.webshield.crawler;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe tracker to prevent duplicate visits and crawl loops.
 */
public class VisitedURLTracker {

    private final Set<String> visitedUrls = ConcurrentHashMap.newKeySet();
    private final Set<String> queuedUrls = ConcurrentHashMap.newKeySet();

    /**
     * Attempts to add a URL to the queue set. Returns true if it was newly added.
     */
    public boolean queueUrl(String url) {
        if (url == null) return false;
        return queuedUrls.add(url);
    }

    /**
     * Marks a URL as visited. Returns true if it was not already marked visited.
     */
    public boolean markVisited(String url) {
        if (url == null) return false;
        return visitedUrls.add(url);
    }

    public boolean isVisited(String url) {
        return url != null && visitedUrls.contains(url);
    }

    public boolean isQueued(String url) {
        return url != null && queuedUrls.contains(url);
    }

    public int getVisitedCount() {
        return visitedUrls.size();
    }

    public int getQueuedCount() {
        return queuedUrls.size();
    }

    public Set<String> getVisitedUrls() {
        return Collections.unmodifiableSet(visitedUrls);
    }

    public void clear() {
        visitedUrls.clear();
        queuedUrls.clear();
    }
}

