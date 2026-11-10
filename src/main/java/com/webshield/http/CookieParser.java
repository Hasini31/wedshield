package com.webshield.http;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Parses Set-Cookie response header directives into {@link HttpCookieData}.
 */
public class CookieParser {

    /**
     * Parses a list of raw Set-Cookie header strings.
     */
    public List<HttpCookieData> parseCookies(List<String> setCookieHeaders) {
        if (setCookieHeaders == null || setCookieHeaders.isEmpty()) {
            return Collections.emptyList();
        }
        List<HttpCookieData> cookies = new ArrayList<>();
        for (String raw : setCookieHeaders) {
            HttpCookieData cookie = parseSingleCookie(raw);
            if (cookie != null) {
                cookies.add(cookie);
            }
        }
        return Collections.unmodifiableList(cookies);
    }

    /**
     * Parses a single Set-Cookie header value string.
     */
    public HttpCookieData parseSingleCookie(String rawCookie) {
        if (rawCookie == null || rawCookie.trim().isEmpty()) {
            return null;
        }

        String[] parts = rawCookie.split(";");
        if (parts.length == 0) {
            return null;
        }

        String nameValue = parts[0].trim();
        int eqIdx = nameValue.indexOf('=');
        if (eqIdx <= 0) {
            return null; // invalid cookie name/value pair
        }

        String name = nameValue.substring(0, eqIdx).trim();
        String value = nameValue.substring(eqIdx + 1).trim();

        String domain = null;
        String path = "/";
        boolean secure = false;
        boolean httpOnly = false;
        String sameSite = null;
        long maxAge = -1;

        for (int i = 1; i < parts.length; i++) {
            String attr = parts[i].trim();
            if (attr.equalsIgnoreCase("secure")) {
                secure = true;
            } else if (attr.equalsIgnoreCase("httponly")) {
                httpOnly = true;
            } else {
                int attrEq = attr.indexOf('=');
                if (attrEq > 0) {
                    String attrName = attr.substring(0, attrEq).trim();
                    String attrVal = attr.substring(attrEq + 1).trim();
                    if (attrName.equalsIgnoreCase("domain")) {
                        domain = attrVal;
                    } else if (attrName.equalsIgnoreCase("path")) {
                        path = attrVal;
                    } else if (attrName.equalsIgnoreCase("samesite")) {
                        sameSite = attrVal;
                    } else if (attrName.equalsIgnoreCase("max-age")) {
                        try {
                            maxAge = Long.parseLong(attrVal);
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }
        }

        return new HttpCookieData(name, value, domain, path, secure, httpOnly, sameSite, maxAge);
    }
}

