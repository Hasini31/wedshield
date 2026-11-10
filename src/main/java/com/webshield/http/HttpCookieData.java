package com.webshield.http;

import java.util.Locale;

/**
 * Encapsulates a parsed HTTP Cookie with its security attributes.
 */
public class HttpCookieData {

    private final String name;
    private final String value;
    private final String domain;
    private final String path;
    private final boolean secure;
    private final boolean httpOnly;
    private final String sameSite; // 'Strict', 'Lax', 'None', or null if unspecified
    private final long maxAge;

    public HttpCookieData(String name, String value, String domain, String path,
                          boolean secure, boolean httpOnly, String sameSite, long maxAge) {
        this.name = name;
        this.value = value;
        this.domain = domain;
        this.path = path != null ? path : "/";
        this.secure = secure;
        this.httpOnly = httpOnly;
        this.sameSite = sameSite != null ? sameSite.toUpperCase(Locale.ROOT) : null;
        this.maxAge = maxAge;
    }

    public String getName() { return name; }
    public String getValue() { return value; }
    public String getDomain() { return domain; }
    public String getPath() { return path; }
    public boolean isSecure() { return secure; }
    public boolean isHttpOnly() { return httpOnly; }
    public String getSameSite() { return sameSite; }
    public long getMaxAge() { return maxAge; }

    @Override
    public String toString() {
        return name + "=" + (value != null && value.length() > 10 ? value.substring(0, 10) + "..." : value)
                + " [Secure=" + secure + ", HttpOnly=" + httpOnly + ", SameSite=" + sameSite + "]";
    }
}

