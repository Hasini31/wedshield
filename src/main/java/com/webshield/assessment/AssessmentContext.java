package com.webshield.assessment;

import com.webshield.crawler.DiscoveredPage;
import com.webshield.http.HttpClientManager;
import com.webshield.models.Website;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Context provided to each assessment rule containing target configuration,
 * discovered pages, and HTTP communication capabilities.
 */
public class AssessmentContext {

    private final Website website;
    private final HttpClientManager httpManager;
    private final List<DiscoveredPage> discoveredPages;
    private final AtomicBoolean cancelled;

    public interface ScanProgressListener {
        void onProgress(int completedChecks, int totalChecks, String currentCheckName, String currentUrl);
    }

    public AssessmentContext(Website website, HttpClientManager httpManager,
                             List<DiscoveredPage> discoveredPages, AtomicBoolean cancelled) {
        this.website = website;
        this.httpManager = httpManager;
        this.discoveredPages = discoveredPages != null ? discoveredPages : List.of();
        this.cancelled = cancelled != null ? cancelled : new AtomicBoolean(false);
    }

    public Website getWebsite() { return website; }
    public HttpClientManager getHttpManager() { return httpManager; }
    public List<DiscoveredPage> getDiscoveredPages() { return Collections.unmodifiableList(discoveredPages); }
    public boolean isCancelled() { return cancelled.get(); }
}

