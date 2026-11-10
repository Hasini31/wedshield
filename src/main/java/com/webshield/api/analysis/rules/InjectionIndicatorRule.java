package com.webshield.api.analysis.rules;

import com.webshield.api.analysis.ApiFindingConfidence;
import com.webshield.api.analysis.ApiFindingSeverity;
import com.webshield.api.analysis.ApiSecurityFinding;
import com.webshield.api.analysis.ApiSecurityRule;
import com.webshield.api.analysis.CweMapping;
import com.webshield.api.analysis.OwaspApiCategory;
import com.webshield.api.execution.ApiExecutionRequest;
import com.webshield.api.execution.ApiExecutionResponse;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects database error disclosures and unhandled application stack traces in API response bodies.
 * Distinguishes information exposure (CWE-209) from confirmed injection exploitation.
 */
@Component
public class InjectionIndicatorRule implements ApiSecurityRule {

    public static final String RULE_ID = "RULE-INJECTION-INDICATOR";

    private static final List<Pattern> SQL_ERROR_PATTERNS = List.of(
            // MySQL
            Pattern.compile("(?i)You have an error in your SQL syntax"),
            Pattern.compile("(?i)check the manual that corresponds to your (?:MySQL|MariaDB) server version"),
            Pattern.compile("(?i)\\bcom\\.mysql\\.cj\\.jdbc\\.exceptions\\b"),
            // PostgreSQL
            Pattern.compile("(?i)syntax error at or near"),
            Pattern.compile("(?i)\\borg\\.postgresql\\.util\\.PSQLException\\b"),
            // Oracle
            Pattern.compile("(?i)\\bORA-[0-9]{5}\\b"),
            Pattern.compile("(?i)Oracle error"),
            // SQLite
            Pattern.compile("(?i)sqlite3\\.OperationalError"),
            Pattern.compile("(?i)SQLite/JDBCDriver"),
            // Microsoft SQL Server
            Pattern.compile("(?i)Unclosed quotation mark after the character string"),
            Pattern.compile("(?i)Microsoft OLE DB Provider for SQL Server"),
            // Generic SQL / ORM
            Pattern.compile("(?i)\\bSQLSTATE\\[[a-zA-Z0-9]+\\]"),
            Pattern.compile("(?i)\\borg\\.hibernate\\.exception\\.(?:SQLGrammarException|GenericJDBCException)\\b")
    );

    private static final List<Pattern> STACK_TRACE_PATTERNS = List.of(
            // Java stack trace
            Pattern.compile("(?m)^\\s*at\\s+[a-zA-Z0-9_.$]+\\([a-zA-Z0-9_.]+\\.java:\\d+\\)"),
            Pattern.compile("(?i)\\b(?:java\\.lang\\.|org\\.springframework\\.)[A-Za-z]+Exception:\\s*"),
            Pattern.compile("(?i)Exception in thread \"[^\"]+\" java\\.lang\\."),
            // Python traceback
            Pattern.compile("(?i)Traceback \\(most recent call last\\):"),
            // Node.js stack trace
            Pattern.compile("(?i)\\bat Object\\.<anonymous> \\([^)]+\\.js:\\d+:\\d+\\)"),
            // PHP stack trace
            Pattern.compile("(?i)(?:Fatal error|Uncaught Exception):[\\s\\S]*?Stack trace:")
    );

    @Override
    public String getRuleId() {
        return RULE_ID;
    }

    @Override
    public String getName() {
        return "Injection and Stack Trace Indicator Detection";
    }

    @Override
    public String getDescription() {
        return "Detects unhandled SQL database errors and full application exception stack traces disclosed in responses.";
    }

    @Override
    public ApiFindingSeverity getSeverity() {
        return ApiFindingSeverity.HIGH;
    }

    @Override
    public OwaspApiCategory getOwaspCategory() {
        return OwaspApiCategory.API8_SECURITY_MISCONFIGURATION;
    }

    @Override
    public String getCweId() {
        return CweMapping.CWE_209;
    }

    @Override
    public String getRemediation() {
        return "Implement global exception handlers to capture database and runtime errors, logging details internally while returning generic, sanitized error responses to API consumers.";
    }

    @Override
    public List<ApiSecurityFinding> analyze(ApiExecutionRequest request, ApiExecutionResponse response) {
        List<ApiSecurityFinding> findings = new ArrayList<>();
        if (response == null || !response.connectionSuccessful()) {
            return findings;
        }

        String body = response.responseBody();
        if (body == null || body.isBlank()) {
            return findings;
        }

        String path = request != null ? request.resolvedPath() : "/";
        Long projectId = request != null ? request.apiProjectId() : null;
        var method = request != null ? request.method() : null;
        String executionId = response.executionId();

        // 1. SQL / Database Error Signatures
        for (Pattern p : SQL_ERROR_PATTERNS) {
            Matcher m = p.matcher(body);
            if (m.find()) {
                String match = m.group();
                String evidenceSnippet = extractContext(body, m.start(), m.end());

                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Information Disclosure: Database SQL Error Message Disclosed")
                        .description("Response discloses raw SQL syntax or database driver error messages ('" + match + "'), indicating unhandled queries and potential SQL injection vulnerability.")
                        .severity(ApiFindingSeverity.HIGH)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("query/body")
                        .evidence("Database error signature: " + evidenceSnippet)
                        .cweId(CweMapping.CWE_209)
                        .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                        .remediation("Use parameterized queries (PreparedStatements / ORM binding) and handle SQL exceptions without returning internal error messages.")
                        .executionId(executionId)
                        .isConfirmed(true) // Confirmed CWE-209 information disclosure
                        .build());
                break; // One SQL error disclosure finding per response is sufficient
            }
        }

        // 2. Application Stack Traces
        for (Pattern p : STACK_TRACE_PATTERNS) {
            Matcher m = p.matcher(body);
            if (m.find()) {
                String evidenceSnippet = extractContext(body, m.start(), m.end());

                findings.add(ApiSecurityFinding.builder()
                        .ruleId(RULE_ID)
                        .title("Information Disclosure: Unhandled Application Stack Trace Disclosed")
                        .description("Response body contains an unhandled application stack trace, revealing internal source file names, packages, and code line numbers.")
                        .severity(ApiFindingSeverity.MEDIUM)
                        .confidence(ApiFindingConfidence.HIGH)
                        .apiProjectId(projectId)
                        .httpMethod(method)
                        .endpointPath(path)
                        .parameterOrField("stack_trace")
                        .evidence("Stack trace snippet: " + evidenceSnippet)
                        .cweId(CweMapping.CWE_209)
                        .owaspCategory(OwaspApiCategory.API8_SECURITY_MISCONFIGURATION)
                        .remediation("Configure application error handling (e.g., @ControllerAdvice in Spring) to suppress verbose stack traces in HTTP responses.")
                        .executionId(executionId)
                        .isConfirmed(true)
                        .build());
                break; // One stack trace finding per response is sufficient
            }
        }

        return findings;
    }

    private static String extractContext(String text, int start, int end) {
        int s = Math.max(0, start - 20);
        int e = Math.min(text.length(), end + 40);
        String sub = text.substring(s, e).replace("\r", " ").replace("\n", " ");
        if (sub.length() > 120) {
            return sub.substring(0, 117) + "...";
        }
        return sub;
    }
}

