package com.webshield.api.analysis;

/**
 * OWASP API Security Top 10 (2023 Edition) vulnerability categories.
 */
public enum OwaspApiCategory {
    API1_BOLA("API1:2023", "Broken Object Level Authorization"),
    API2_BROKEN_AUTH("API2:2023", "Broken Authentication"),
    API3_BOPLA("API3:2023", "Broken Object Property Level Authorization"),
    API4_UNRESTRICTED_RESOURCE_CONSUMPTION("API4:2023", "Unrestricted Resource Consumption"),
    API5_BFLA("API5:2023", "Broken Function Level Authorization"),
    API6_UNRESTRICTED_ACCESS_SENSITIVE_BUSINESS_FLOWS("API6:2023", "Unrestricted Access to Sensitive Business Flows"),
    API7_SSRF("API7:2023", "Server Side Request Forgery"),
    API8_SECURITY_MISCONFIGURATION("API8:2023", "Security Misconfiguration"),
    API9_IMPROPER_INVENTORY_MANAGEMENT("API9:2023", "Improper Inventory Management"),
    API10_UNSAFE_CONSUMPTION_OF_APIS("API10:2023", "Unsafe Consumption of APIs");

    private final String code;
    private final String title;

    OwaspApiCategory(String code, String title) {
        this.code = code;
        this.title = title;
    }

    public String getCode() {
        return code;
    }

    public String getTitle() {
        return title;
    }

    public String getDisplayName() {
        return code + " - " + title;
    }
}

