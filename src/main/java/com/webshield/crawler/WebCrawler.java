package com.webshield.crawler;

import com.webshield.http.HttpClientManager;
import com.webshield.http.HttpRequestBuilder;
import com.webshield.http.HttpRequestData;
import com.webshield.http.HttpResponseData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import org.springframework.stereotype.Component;

/**
 * Autonomous web crawler executing breadth-first discovery of an authorized web application.
 * Adapts architectural patterns from OWASP ZAP's {@code Spider}.
 */
@Component
public class WebCrawler {

    private static final Logger log = LoggerFactory.getLogger(WebCrawler.class);

    private final HttpClientManager httpManager;
    private final LinkExtractor linkExtractor;
    private final FormExtractor formExtractor;
    private final URLNormalizer normalizer;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    public interface CrawlProgressListener {
        void onProgress(int pagesDiscovered, int formsDiscovered, String currentUrl);
    }

    public WebCrawler() {
        this(com.webshield.config.SpringContext.getBean(HttpClientManager.class) != null
                ? com.webshield.config.SpringContext.getBean(HttpClientManager.class) : new HttpClientManager());
    }

    public WebCrawler(HttpClientManager httpManager) {
        this.httpManager = httpManager;
        this.linkExtractor = new LinkExtractor();
        this.formExtractor = new FormExtractor();
        this.normalizer = new URLNormalizer();
    }

    public void cancel() {
        this.cancelled.set(true);
    }

    public boolean isCancelled() {
        return this.cancelled.get();
    }

    /**
     * Executes the crawl according to the supplied configuration.
     */
    public CrawlResult crawl(CrawlConfiguration config, CrawlProgressListener listener) {
        cancelled.set(false);
        long startTime = System.currentTimeMillis();

        String seedUrl = normalizer.normalize(config.getTargetUrl(), null)
                .orElse(config.getTargetUrl());

        URLDiscovery scope = new URLDiscovery(config.getTargetDomain(), config.isAllowLocalhost());
        VisitedURLTracker visitedTracker = new VisitedURLTracker();

        Queue<CrawlQueueItem> queue = new ArrayDeque<>();
        List<DiscoveredPage> pages = new ArrayList<>();

        if (scope.isInScope(seedUrl)) {
            queue.add(new CrawlQueueItem(seedUrl, 0));
            visitedTracker.queueUrl(seedUrl);
        } else {
            log.warn("Seed URL rejected by scope check: {}", seedUrl);
            return new CrawlResult(seedUrl, pages, System.currentTimeMillis() - startTime, "SCOPE_REJECTED");
        }

        int formsCount = 0;

        while (!queue.isEmpty() && !cancelled.get()) {
            if (pages.size() >= config.getMaxPages()) {
                log.info("Reached maximum page limit of {}", config.getMaxPages());
                break;
            }

            CrawlQueueItem item = queue.poll();
            String currentUrl = item.url;
            int currentDepth = item.depth;

            if (visitedTracker.isVisited(currentUrl)) {
                continue;
            }
            visitedTracker.markVisited(currentUrl);

            if (listener != null) {
                listener.onProgress(pages.size() + 1, formsCount, currentUrl);
            }

            // Execute HTTP GET
            try {
                HttpRequestData req = HttpRequestBuilder.get(currentUrl)
                        .timeout(config.getRequestTimeoutSeconds())
                        .build();

                HttpResponseData res = httpManager.execute(req, config.getTargetDomain());

                DiscoveredPage page = new DiscoveredPage(currentUrl, currentDepth);
                page.setStatusCode(res.getStatusCode());
                page.setContentType(res.getContentType());
                page.setPageTitle(linkExtractor.extractTitle(res.getBody()));

                // Extract forms
                List<DiscoveredForm> forms = formExtractor.extractForms(res.getBody(), currentUrl);
                for (DiscoveredForm f : forms) {
                    page.addForm(f);
                    formsCount++;
                }

                pages.add(page);

                // Queue next links if depth permits and content is HTML
                if (currentDepth < config.getMaxDepth() && isHtml(res.getContentType())) {
                    Set<String> discoveredLinks = linkExtractor.extractLinks(res.getBody(), currentUrl);
                    for (String link : discoveredLinks) {
                        if (scope.isInScope(link) && !visitedTracker.isVisited(link) && visitedTracker.queueUrl(link)) {
                            queue.add(new CrawlQueueItem(link, currentDepth + 1));
                        }
                    }
                }

                // Rate limiting delay
                if (config.getDelayBetweenRequestsMs() > 0) {
                    try {
                        Thread.sleep(config.getDelayBetweenRequestsMs());
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }

            } catch (Exception e) {
                log.warn("Crawl request failed for {}: {}", currentUrl, e.getMessage());
            }
        }

        long duration = System.currentTimeMillis() - startTime;
        String finalStatus = cancelled.get() ? "CANCELLED" : "COMPLETED";
        log.info("Crawling {} completed: {} pages discovered, {} forms in {}ms",
                seedUrl, pages.size(), formsCount, duration);

        return new CrawlResult(seedUrl, pages, duration, finalStatus);
    }

    private boolean isHtml(String contentType) {
        if (contentType == null) return false;
        String lower = contentType.toLowerCase(Locale.ROOT);
        return lower.contains("text/html") || lower.contains("application/xhtml");
    }

    private static class CrawlQueueItem {
        final String url;
        final int depth;

        CrawlQueueItem(String url, int depth) {
            this.url = url;
            this.depth = depth;
        }
    }
}

