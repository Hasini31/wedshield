package com.webshield.assessment.analyzers;

import com.webshield.assessment.AssessmentContext;
import com.webshield.assessment.AssessmentRule;
import com.webshield.assessment.models.AssessmentResult;
import com.webshield.assessment.models.ConfidenceLevel;
import com.webshield.assessment.models.Severity;
import com.webshield.crawler.DiscoveredPage;
import com.webshield.crawler.ParameterExtractor;
import com.webshield.http.HttpRequestBuilder;
import com.webshield.http.HttpRequestData;
import com.webshield.http.HttpResponseData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Detects database management system (DBMS) error signatures in HTTP responses.
 * Reference: OWASP ZAP SqlInjectionScanner error regex catalogue.
 */
@Component
public class SqlErrorAnalyzer implements AssessmentRule {

    private static final Logger log = LoggerFactory.getLogger(SqlErrorAnalyzer.class);
    private final ParameterExtractor paramExtractor = new ParameterExtractor();

    private static final List<DbmsErrorPattern> DBMS_PATTERNS = List.of(
            // MySQL / MariaDB
            new DbmsErrorPattern("MySQL", Pattern.compile("you have an error in your sql syntax", Pattern.CASE_INSENSITIVE)),
            new DbmsErrorPattern("MySQL", Pattern.compile("warning:\\s+mysql_", Pattern.CASE_INSENSITIVE)),
            new DbmsErrorPattern("MySQL", Pattern.compile("valid mysql result", Pattern.CASE_INSENSITIVE)),
            new DbmsErrorPattern("MySQL", Pattern.compile("com\\.mysql\\.jdbc\\.exceptions", Pattern.CASE_INSENSITIVE)),

            // PostgreSQL
            new DbmsErrorPattern("PostgreSQL", Pattern.compile("postgresql query failed", Pattern.CASE_INSENSITIVE)),
            new DbmsErrorPattern("PostgreSQL", Pattern.compile("org\\.postgresql\\.util\\.psqlexception", Pattern.CASE_INSENSITIVE)),
            new DbmsErrorPattern("PostgreSQL", Pattern.compile("syntax error at or near", Pattern.CASE_INSENSITIVE)),
            new DbmsErrorPattern("PostgreSQL", Pattern.compile("pg_query\\(\\)", Pattern.CASE_INSENSITIVE)),

            // Microsoft SQL Server
            new DbmsErrorPattern("MS SQL Server", Pattern.compile("unclosed quotation mark after the character string", Pattern.CASE_INSENSITIVE)),
            new DbmsErrorPattern("MS SQL Server", Pattern.compile("microsoft ole db provider for sql server", Pattern.CASE_INSENSITIVE)),
            new DbmsErrorPattern("MS SQL Server", Pattern.compile("\\[sql server\\]", Pattern.CASE_INSENSITIVE)),

            // Oracle
            new DbmsErrorPattern("Oracle", Pattern.compile("ora-[0-9]{4,5}:", Pattern.CASE_INSENSITIVE)),
            new DbmsErrorPattern("Oracle", Pattern.compile("quoted string not properly terminated", Pattern.CASE_INSENSITIVE)),

            // SQLite
            new DbmsErrorPattern("SQLite", Pattern.compile("sqlite3::sqlexception", Pattern.CASE_INSENSITIVE)),
            new DbmsErrorPattern("SQLite", Pattern.compile("sqlite error", Pattern.CASE_INSENSITIVE))
    );

    @Override
    public String getRuleId() { return "WS-RULE-SQL-ERROR"; }

    @Override
    public String getName() { return "SQL Error and Anomaly Detection"; }

    @Override
    public String getCategory() { return "Injection"; }

    @Override
    public List<AssessmentResult> analyze(AssessmentContext context, DiscoveredPage page, HttpResponseData response) {
        List<AssessmentResult> results = new ArrayList<>();
        if (response == null || response.getBody() == null) {
            return results;
        }

        // Passive inspection of normal response
        checkDbmsErrors(response.getBody()).ifPresent(match -> {
            results.add(new AssessmentResult(
                    "SQL Error Message Disclosure",
                    "Injection",
                    "WS-SQL-001",
                    page.getUrl(),
                    null,
                    page.getHttpMethod(),
                    Severity.HIGH,
                    ConfidenceLevel.CONFIRMED,
                    "Database error message indicating " + match.dbms + " was detected in the HTTP response. Leaking database error messages assists attackers in constructing SQL injection exploits.",
                    "DBMS: " + match.dbms + " | Error excerpt: " + match.matchedSnippet,
                    "Passive Response Inspection",
                    "Configure the application and web server to suppress raw database exception messages. Display generic user-friendly error pages."
            ));
        });

        return results;
    }

    @Override
    public List<AssessmentResult> probe(AssessmentContext context, DiscoveredPage page) {
        List<AssessmentResult> results = new ArrayList<>();
        if (context.isCancelled() || page.getUrl() == null) {
            return results;
        }

        String targetDomain = context.getWebsite().getUrl();
        Map<String, List<String>> queryParams = paramExtractor.extractQueryParameters(page.getUrl());

        for (String param : queryParams.keySet()) {
            if (context.isCancelled()) break;

            // Safe single quote anomaly probe
            String probeUrl = appendParamValue(page.getUrl(), param, "'");
            try {
                HttpRequestData req = HttpRequestBuilder.get(probeUrl).timeout(10).build();
                HttpResponseData res = context.getHttpManager().execute(req, targetDomain);

                checkDbmsErrors(res.getBody()).ifPresent(match -> {
                    results.add(new AssessmentResult(
                            "SQL Error Disclosed on Syntax Probe",
                            "Injection",
                            "WS-SQL-001",
                            page.getUrl(),
                            param,
                            "GET",
                            Severity.HIGH,
                            ConfidenceLevel.CONFIRMED,
                            "Injecting a single quotation mark into parameter '" + param + "' provoked a recognizable " + match.dbms + " syntax error. This confirms raw SQL error disclosure and strongly indicates SQL injection potential.",
                            "Parameter: " + param + " | Probe: ' | DBMS: " + match.dbms + " | Excerpt: " + match.matchedSnippet,
                            "Non-destructive Syntax Anomaly Probe",
                            "Use parameterized queries (PreparedStatements) for all database operations and disable verbose error messages in production."
                    ));
                });
            } catch (Exception e) {
                log.debug("SQL error probe failed on {}: {}", probeUrl, e.getMessage());
            }
        }

        return results;
    }

    public Optional<MatchedError> checkDbmsErrors(String text) {
        if (text == null || text.isEmpty()) return Optional.empty();

        for (DbmsErrorPattern dep : DBMS_PATTERNS) {
            Matcher matcher = dep.pattern.matcher(text);
            if (matcher.find()) {
                int start = Math.max(0, matcher.start() - 30);
                int end = Math.min(text.length(), matcher.end() + 30);
                String snippet = text.substring(start, end).replaceAll("\\s+", " ").trim();
                return Optional.of(new MatchedError(dep.dbms, snippet));
            }
        }
        return Optional.empty();
    }

    private String appendParamValue(String url, String paramName, String appendValue) {
        try {
            URI uri = new URI(url);
            String rawQuery = uri.getRawQuery();
            if (rawQuery == null) return url;

            StringBuilder sb = new StringBuilder();
            String[] pairs = rawQuery.split("&");
            for (String pair : pairs) {
                if (!sb.isEmpty()) sb.append("&");
                int idx = pair.indexOf("=");
                String key = idx > 0 ? pair.substring(0, idx) : pair;
                String val = idx > 0 && pair.length() > idx + 1 ? pair.substring(idx + 1) : "";
                if (key.equalsIgnoreCase(paramName)) {
                    sb.append(key).append("=").append(val).append(URLEncoder.encode(appendValue, StandardCharsets.UTF_8));
                } else {
                    sb.append(pair);
                }
            }

            URI newUri = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(),
                    uri.getPort(), uri.getPath(), sb.toString(), null);
            return newUri.toString();
        } catch (Exception e) {
            return url;
        }
    }

    private static class DbmsErrorPattern {
        final String dbms;
        final Pattern pattern;

        DbmsErrorPattern(String dbms, Pattern pattern) {
            this.dbms = dbms;
            this.pattern = pattern;
        }
    }

    public static class MatchedError {
        public final String dbms;
        public final String matchedSnippet;

        public MatchedError(String dbms, String matchedSnippet) {
            this.dbms = dbms;
            this.matchedSnippet = matchedSnippet;
        }
    }
}

