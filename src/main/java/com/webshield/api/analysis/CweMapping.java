package com.webshield.api.analysis;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Common Weakness Enumeration (CWE) constants and mapping helpers for API security findings.
 */
public final class CweMapping {

    public static final String CWE_16 = "CWE-16";   // Configuration
    public static final String CWE_20 = "CWE-20";   // Improper Input Validation
    public static final String CWE_89 = "CWE-89";   // SQL Injection
    public static final String CWE_200 = "CWE-200"; // Exposure of Sensitive Information
    public static final String CWE_209 = "CWE-209"; // Error Message Containing Sensitive Information
    public static final String CWE_284 = "CWE-284"; // Improper Access Control
    public static final String CWE_287 = "CWE-287"; // Improper Authentication
    public static final String CWE_319 = "CWE-319"; // Cleartext Transmission of Sensitive Information
    public static final String CWE_522 = "CWE-522"; // Insufficiently Protected Credentials
    public static final String CWE_524 = "CWE-524"; // Use of Cache-control without Proper Protection
    public static final String CWE_598 = "CWE-598"; // Use of GET Request Method With Sensitive Query Strings
    public static final String CWE_693 = "CWE-693"; // Protection Mechanism Failure
    public static final String CWE_754 = "CWE-754"; // Improper Check for Unusual or Exceptional Conditions

    private static final Map<String, String> DESCRIPTIONS;

    static {
        Map<String, String> map = new LinkedHashMap<>();
        map.put(CWE_16, "Configuration: The product is configured in an insecure manner.");
        map.put(CWE_20, "Improper Input Validation: The product receives input or data, but does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.");
        map.put(CWE_89, "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'): The software constructs an SQL command using externally-influenced input from an upstream component, but fails to neutralize special elements.");
        map.put(CWE_200, "Exposure of Sensitive Information to an Unauthorized Actor: The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.");
        map.put(CWE_209, "Generation of Error Message Containing Sensitive Information: The software generates an error message that includes sensitive information about its environment, users, or associated data.");
        map.put(CWE_284, "Improper Access Control: The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor.");
        map.put(CWE_287, "Improper Authentication: When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.");
        map.put(CWE_319, "Cleartext Transmission of Sensitive Information: The software transmits sensitive data in cleartext over a communication channel that can be sniffed by unauthorized actors.");
        map.put(CWE_522, "Insufficiently Protected Credentials: The product transmits or stores authentication credentials, but does not adequately protect them from unauthorized actors.");
        map.put(CWE_524, "Use of Cache-control without Proper Protection: The web application does not specify appropriate caching directives, resulting in sensitive data being cached.");
        map.put(CWE_598, "Use of GET Request Method With Sensitive Query Strings: The web application uses the GET method to submit sensitive data, exposing it in web server logs, referrer headers, and browser histories.");
        map.put(CWE_693, "Protection Mechanism Failure: The software does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks.");
        map.put(CWE_754, "Improper Check for Unusual or Exceptional Conditions: The product does not check or incorrectly checks for unusual or exceptional conditions, which can lead to unexpected exceptions or crashes.");
        DESCRIPTIONS = Collections.unmodifiableMap(map);
    }

    private CweMapping() {
        // utility class
    }

    public static String getDescription(String cweId) {
        if (cweId == null) return "Unknown CWE";
        return DESCRIPTIONS.getOrDefault(cweId, "CWE definition for " + cweId);
    }

    public static String getUrl(String cweId) {
        if (cweId == null || !cweId.startsWith("CWE-")) {
            return "https://cwe.mitre.org";
        }
        String idNumber = cweId.substring(4);
        return "https://cwe.mitre.org/data/definitions/" + idNumber + ".html";
    }
}

