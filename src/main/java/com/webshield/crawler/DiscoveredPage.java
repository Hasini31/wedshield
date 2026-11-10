package com.webshield.crawler;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Encapsulates a web page discovered during a crawl.
 */
public class DiscoveredPage {

    private long id;
    private long scanId;
    private long websiteId;
    private final String url;
    private String pageTitle;
    private String httpMethod = "GET";
    private int statusCode = 200;
    private String contentType = "text/html";
    private int depth = 0;
    private boolean hasForms = false;
    private boolean wasTested = false;
    private LocalDateTime discoveredAt;
    private final List<DiscoveredForm> forms;

    public DiscoveredPage(String url, int depth) {
        this.url = url;
        this.depth = depth;
        this.forms = new ArrayList<>();
        this.discoveredAt = LocalDateTime.now();
    }

    public long getId() { return id; }
    public void setId(long id) { this.id = id; }
    public long getScanId() { return scanId; }
    public void setScanId(long scanId) { this.scanId = scanId; }
    public long getWebsiteId() { return websiteId; }
    public void setWebsiteId(long websiteId) { this.websiteId = websiteId; }

    public String getUrl() { return url; }
    public String getPageTitle() { return pageTitle; }
    public void setPageTitle(String pageTitle) { this.pageTitle = pageTitle; }

    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }

    public int getStatusCode() { return statusCode; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }

    public String getContentType() { return contentType; }
    public void setContentType(String contentType) { this.contentType = contentType; }

    public int getDepth() { return depth; }
    public void setDepth(int depth) { this.depth = depth; }

    public boolean isHasForms() { return hasForms; }
    public void setHasForms(boolean hasForms) { this.hasForms = hasForms; }

    public boolean isWasTested() { return wasTested; }
    public void setWasTested(boolean wasTested) { this.wasTested = wasTested; }

    public LocalDateTime getDiscoveredAt() { return discoveredAt; }
    public void setDiscoveredAt(LocalDateTime discoveredAt) { this.discoveredAt = discoveredAt; }

    public List<DiscoveredForm> getForms() { return Collections.unmodifiableList(forms); }

    public void addForm(DiscoveredForm form) {
        if (form != null) {
            this.forms.add(form);
            this.hasForms = true;
        }
    }

    @Override
    public String toString() {
        return url + " (" + statusCode + ", depth=" + depth + ")";
    }
}

