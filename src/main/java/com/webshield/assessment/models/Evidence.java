package com.webshield.assessment.models;

/**
 * Concrete technical evidence corroborating a security assessment finding.
 */
public class Evidence {

    private final String affectedUrl;
    private final String parameter;
    private final String detectionMethod;
    private final String excerpt;
    private final String requestHeaders;

    public Evidence(String affectedUrl, String parameter, String detectionMethod,
                    String excerpt, String requestHeaders) {
        this.affectedUrl = affectedUrl;
        this.parameter = parameter;
        this.detectionMethod = detectionMethod;
        this.excerpt = excerpt;
        this.requestHeaders = requestHeaders;
    }

    public String getAffectedUrl() { return affectedUrl; }
    public String getParameter() { return parameter; }
    public String getDetectionMethod() { return detectionMethod; }
    public String getExcerpt() { return excerpt; }
    public String getRequestHeaders() { return requestHeaders; }

    @Override
    public String toString() {
        return "[" + detectionMethod + "] " + excerpt;
    }
}

