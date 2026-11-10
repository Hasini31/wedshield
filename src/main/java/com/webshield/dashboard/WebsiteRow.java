package com.webshield.dashboard;

/**
 * Lightweight row returned by the "recent websites" query.
 */
public class WebsiteRow {
    private final long   id;
    private final String name;
    private final String url;
    private final String registeredAt;
    private final String lastScan;
    private final String status;

    public WebsiteRow(long id, String name, String url,
                      String registeredAt, String lastScan, String status) {
        this.id           = id;
        this.name         = name;
        this.url          = url;
        this.registeredAt = registeredAt;
        this.lastScan     = lastScan;
        this.status       = status;
    }

    public long   getId()           { return id;           }
    public String getName()         { return name;         }
    public String getUrl()          { return url;          }
    public String getRegisteredAt() { return registeredAt; }
    public String getLastScan()     { return lastScan;     }
    public String getStatus()       { return status;       }
}

