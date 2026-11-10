package com.webshield.api.analysis;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility for sanitizing and redacting sensitive data (passwords, tokens, keys, credentials)
 * from evidence strings and findings to prevent accidental credential leakage in test reports.
 */
public final class RedactionUtils {

    private static final Pattern PASSWORD_JSON_PATTERN = Pattern.compile(
            "(?i)\"(password|passwd|pwd|secret|client_secret|user_password|db_password)\"\\s*:\\s*\"([^\"]+)\"");

    private static final Pattern BEARER_TOKEN_PATTERN = Pattern.compile(
            "(?i)(Bearer\\s+)[A-Za-z0-9._~+/-]{10,}");

    private static final Pattern BASIC_AUTH_PATTERN = Pattern.compile(
            "(?i)(Basic\\s+)[A-Za-z0-9+/=]{10,}");

    private static final Pattern AWS_KEY_PATTERN = Pattern.compile(
            "\\bAKIA[0-9A-Z]{16}\\b");

    private static final Pattern STRIPE_KEY_PATTERN = Pattern.compile(
            "\\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\\b");

    private static final Pattern GITHUB_TOKEN_PATTERN = Pattern.compile(
            "\\bghp_[0-9a-zA-Z]{36}\\b");

    private static final Pattern JWT_PATTERN = Pattern.compile(
            "\\beyJ[a-zA-Z0-9_-]{10,}\\.eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}\\b");

    private static final Pattern PRIVATE_KEY_PATTERN = Pattern.compile(
            "-----BEGIN [A-Z0-9 ]+ KEY-----[\\s\\S]*?-----END [A-Z0-9 ]+ KEY-----");

    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile(
            "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b");

    private static final Pattern DB_URL_CREDS_PATTERN = Pattern.compile(
            "(?i)(jdbc:[a-zA-Z0-9:]+://[^:]+:)([^@]+)(@)");

    private static final Pattern PASSWORD_KV_PATTERN = Pattern.compile(
            "(?i)(password|passwd|pwd|secret|client_secret|api_key|token)=([^&\\s]+)");

    private RedactionUtils() {
    }

    /**
     * Sanitizes sensitive information within an evidence or debug string by replacing credentials with masks.
     */
    public static String redactSensitiveData(String input) {
        if (input == null || input.isBlank()) {
            return input;
        }

        String redacted = input;

        // 1. Private keys
        redacted = PRIVATE_KEY_PATTERN.matcher(redacted).replaceAll("[PRIVATE KEY REDACTED]");

        // 2. Passwords in JSON structures & Key-Value pairs
        Matcher passwordMatcher = PASSWORD_JSON_PATTERN.matcher(redacted);
        if (passwordMatcher.find()) {
            redacted = passwordMatcher.replaceAll("\"$1\": \"******\"");
        }
        redacted = PASSWORD_KV_PATTERN.matcher(redacted).replaceAll("$1=******");

        // 3. Bearer & Basic Auth
        redacted = BEARER_TOKEN_PATTERN.matcher(redacted).replaceAll("$1******");
        redacted = BASIC_AUTH_PATTERN.matcher(redacted).replaceAll("$1******");

        // 4. Cloud and API keys
        redacted = AWS_KEY_PATTERN.matcher(redacted).replaceAll("AKIA****************");
        redacted = STRIPE_KEY_PATTERN.matcher(redacted).replaceAll("sk_live_****[REDACTED]");
        redacted = GITHUB_TOKEN_PATTERN.matcher(redacted).replaceAll("ghp_****[REDACTED]");

        // 5. JWT tokens
        redacted = JWT_PATTERN.matcher(redacted).replaceAll("eyJ****...[JWT REDACTED]");

        // 6. DB Connection credentials
        redacted = DB_URL_CREDS_PATTERN.matcher(redacted).replaceAll("$1******$3");

        // 7. Credit card numbers (mask all but last 4 digits)
        Matcher ccMatcher = CREDIT_CARD_PATTERN.matcher(redacted);
        StringBuffer sb = new StringBuffer();
        while (ccMatcher.find()) {
            String cc = ccMatcher.group();
            String last4 = cc.substring(cc.length() - 4);
            ccMatcher.appendReplacement(sb, "****-****-****-" + last4);
        }
        ccMatcher.appendTail(sb);
        redacted = sb.toString();

        return redacted;
    }
}

