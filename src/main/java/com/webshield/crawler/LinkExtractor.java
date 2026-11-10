package com.webshield.crawler;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.*;

/**
 * Extracts hyperlinks from HTML documents using Jsoup.
 * Modeled after OWASP ZAP's {@code SpiderHtmlParser}.
 */
public class LinkExtractor {

    private final URLNormalizer normalizer;

    public LinkExtractor() {
        this(new URLNormalizer());
    }

    public LinkExtractor(URLNormalizer normalizer) {
        this.normalizer = normalizer;
    }

    /**
     * Extracts and normalizes all discovered links from an HTML document.
     */
    public Set<String> extractLinks(String htmlContent, String pageUrl) {
        if (htmlContent == null || htmlContent.trim().isEmpty()) {
            return Collections.emptySet();
        }

        Set<String> discovered = new LinkedHashSet<>();
        try {
            Document doc = Jsoup.parse(htmlContent, pageUrl);

            // 1. Anchor links
            Elements anchors = doc.select("a[href], area[href]");
            for (Element el : anchors) {
                addResolved(discovered, el.attr("href"), pageUrl);
            }

            // 2. Link tags (e.g. alternate, canonical)
            Elements links = doc.select("link[href]");
            for (Element el : links) {
                addResolved(discovered, el.attr("href"), pageUrl);
            }

            // 3. Frames and iframes
            Elements frames = doc.select("frame[src], iframe[src]");
            for (Element el : frames) {
                addResolved(discovered, el.attr("src"), pageUrl);
            }

        } catch (Exception ignored) {}

        return discovered;
    }

    /**
     * Extracts page title from HTML.
     */
    public String extractTitle(String htmlContent) {
        if (htmlContent == null || htmlContent.trim().isEmpty()) {
            return "";
        }
        try {
            Document doc = Jsoup.parse(htmlContent);
            return doc.title();
        } catch (Exception e) {
            return "";
        }
    }

    private void addResolved(Set<String> set, String rawHref, String pageUrl) {
        if (rawHref == null || rawHref.trim().isEmpty()) return;
        normalizer.normalize(rawHref, pageUrl).ifPresent(set::add);
    }
}

