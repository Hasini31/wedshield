package com.webshield.dashboard;

/**
 * Data model for the Website Security Overview table on the Dashboard.
 */
public class WebsiteOverviewRow {
    private final long   id;
    private final String name;
    private final String url;
    private final int    pagesDiscovered;
    private final int    pagesTested;
    private final int    totalFindings;
    private final int    criticalFindings;
    private final int    highFindings;
    private final String lastScan;
    private final String scanStatus;
    private final Long   lastScanId;

    public WebsiteOverviewRow(long id, String name, String url,
                              int pagesDiscovered, int pagesTested,
                              int totalFindings, int criticalFindings, int highFindings,
                              String lastScan, String scanStatus, Long lastScanId) {
        this.id               = id;
        this.name             = name;
        this.url              = url;
        this.pagesDiscovered  = pagesDiscovered;
        this.pagesTested      = pagesTested;
        this.totalFindings    = totalFindings;
        this.criticalFindings = criticalFindings;
        this.highFindings     = highFindings;
        this.lastScan         = lastScan;
        this.scanStatus       = scanStatus;
        this.lastScanId       = lastScanId;
    }

    public long   getId()               { return id; }
    public String getName()             { return name; }
    public String getUrl()              { return url; }
    public int    getPagesDiscovered()  { return pagesDiscovered; }
    public int    getPagesTested()      { return pagesTested; }
    public int    getTotalFindings()    { return totalFindings; }
    public int    getCriticalFindings() { return criticalFindings; }
    public int    getHighFindings()     { return highFindings; }
    public String getLastScan()         { return lastScan; }
    public String getScanStatus()       { return scanStatus; }
    public Long   getLastScanId()       { return lastScanId; }
}
