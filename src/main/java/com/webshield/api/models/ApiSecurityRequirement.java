package com.webshield.api.models;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Authentication requirement and security scheme definition for an API operation.
 */
public class ApiSecurityRequirement {

    private String schemeName;
    private String type;         // http, apiKey, oauth2, openIdConnect
    private String scheme;       // bearer, basic
    private String bearerFormat; // JWT, etc.
    private String in;           // header, query, cookie
    private String paramName;    // X-API-Key, etc.
    private List<String> scopes = new ArrayList<>();

    public ApiSecurityRequirement() {
    }

    public ApiSecurityRequirement(String schemeName, String type, String scheme,
                                  String bearerFormat, String in, String paramName,
                                  List<String> scopes) {
        this.schemeName = schemeName;
        this.type = type;
        this.scheme = scheme;
        this.bearerFormat = bearerFormat;
        this.in = in;
        this.paramName = paramName;
        this.scopes = scopes != null ? new ArrayList<>(scopes) : new ArrayList<>();
    }

    public boolean isBearerAuth() {
        return "http".equalsIgnoreCase(type) && "bearer".equalsIgnoreCase(scheme);
    }

    public boolean isApiKey() {
        return "apiKey".equalsIgnoreCase(type);
    }

    public boolean isBasicAuth() {
        return "http".equalsIgnoreCase(type) && "basic".equalsIgnoreCase(scheme);
    }

    public boolean isOAuth2() {
        return "oauth2".equalsIgnoreCase(type) || "openIdConnect".equalsIgnoreCase(type);
    }

    public String getSchemeName() {
        return schemeName;
    }

    public void setSchemeName(String schemeName) {
        this.schemeName = schemeName;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getScheme() {
        return scheme;
    }

    public void setScheme(String scheme) {
        this.scheme = scheme;
    }

    public String getBearerFormat() {
        return bearerFormat;
    }

    public void setBearerFormat(String bearerFormat) {
        this.bearerFormat = bearerFormat;
    }

    public String getIn() {
        return in;
    }

    public void setIn(String in) {
        this.in = in;
    }

    public String getParamName() {
        return paramName;
    }

    public void setParamName(String paramName) {
        this.paramName = paramName;
    }

    public List<String> getScopes() {
        return Collections.unmodifiableList(scopes);
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes != null ? new ArrayList<>(scopes) : new ArrayList<>();
    }

    public void addScope(String scope) {
        if (scope != null) {
            this.scopes.add(scope);
        }
    }

    @Override
    public String toString() {
        return "ApiSecurityRequirement{" +
                "schemeName='" + schemeName + '\'' +
                ", type='" + type + '\'' +
                (scheme != null ? ", scheme='" + scheme + '\'' : "") +
                '}';
    }
}

