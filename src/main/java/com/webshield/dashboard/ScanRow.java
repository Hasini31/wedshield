package com.webshield.dashboard;

/**
 * Lightweight row returned by the "recent scans" query.
 */
public class ScanRow {
    private final long   id;
    private final String websiteName;
    private final String startedAt;
    private final String status;
    private final int    findingsCount;

    public ScanRow(long id, String websiteName, String startedAt,
                   String status, int findingsCount) {
        this.id           = id;
        this.websiteName  = websiteName;
        this.startedAt    = startedAt;
        this.status       = status;
        this.findingsCount = findingsCount;
    }

    public long   getId()           { return id;            }
    public String getWebsiteName()  { return websiteName;   }
    public String getStartedAt()    { return startedAt;     }
    public String getStatus()       { return status;        }
    public int    getFindingsCount(){ return findingsCount;  }
}

