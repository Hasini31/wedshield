package com.webshield.api.analysis;

import com.webshield.api.models.HttpMethod;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Immutable representation of a security weakness, misconfiguration, or vulnerability
 * discovered during API response analysis.
 */
public record ApiSecurityFinding(
        String findingId,
        String ruleId,
        String title,
        String description,
        ApiFindingSeverity severity,
        ApiFindingConfidence confidence,
        Long apiProjectId,
        HttpMethod httpMethod,
        String endpointPath,
        String parameterOrField,
        String evidence,
        String cweId,
        OwaspApiCategory owaspCategory,
        String remediation,
        Instant detectionTimestamp,
        String executionId,
        boolean isConfirmed
) implements Serializable {

    public ApiSecurityFinding {
        findingId = findingId != null ? findingId : UUID.randomUUID().toString();
        title = title != null ? title : "Security Finding";
        description = description != null ? description : "";
        severity = severity != null ? severity : ApiFindingSeverity.INFORMATIONAL;
        confidence = confidence != null ? confidence : ApiFindingConfidence.MEDIUM;
        endpointPath = endpointPath != null ? endpointPath : "/";
        parameterOrField = parameterOrField != null ? parameterOrField : "";
        evidence = evidence != null ? RedactionUtils.redactSensitiveData(evidence) : "";
        cweId = cweId != null ? cweId : CweMapping.CWE_16;
        owaspCategory = owaspCategory != null ? owaspCategory : OwaspApiCategory.API8_SECURITY_MISCONFIGURATION;
        remediation = remediation != null ? remediation : "Review and apply secure coding best practices.";
        detectionTimestamp = detectionTimestamp != null ? detectionTimestamp : Instant.now();
        executionId = executionId != null ? executionId : "";
    }

    /**
     * Generates a canonical deduplication signature key used to group and eliminate duplicate findings.
     * Pattern: ruleId|endpointPath|httpMethod|parameterOrField|evidenceHash
     */
    public String getDeduplicationKey() {
        String methodStr = httpMethod != null ? httpMethod.name() : "";
        String paramStr = parameterOrField != null ? parameterOrField.trim() : "";
        String pathStr = endpointPath != null ? endpointPath.trim() : "";
        String evidenceHash = hashEvidence(evidence);

        return ruleId + "|" + pathStr + "|" + methodStr + "|" + paramStr + "|" + evidenceHash;
    }

    private static String hashEvidence(String ev) {
        if (ev == null || ev.isBlank()) {
            return "empty";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(ev.trim().toLowerCase().getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < Math.min(hash.length, 8); i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return Integer.toHexString(ev.trim().toLowerCase().hashCode());
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String findingId;
        private String ruleId;
        private String title;
        private String description;
        private ApiFindingSeverity severity = ApiFindingSeverity.INFORMATIONAL;
        private ApiFindingConfidence confidence = ApiFindingConfidence.MEDIUM;
        private Long apiProjectId;
        private HttpMethod httpMethod;
        private String endpointPath;
        private String parameterOrField;
        private String evidence;
        private String cweId = CweMapping.CWE_16;
        private OwaspApiCategory owaspCategory = OwaspApiCategory.API8_SECURITY_MISCONFIGURATION;
        private String remediation;
        private Instant detectionTimestamp;
        private String executionId;
        private boolean isConfirmed = false;

        public Builder findingId(String findingId) { this.findingId = findingId; return this; }
        public Builder ruleId(String ruleId) { this.ruleId = ruleId; return this; }
        public Builder title(String title) { this.title = title; return this; }
        public Builder description(String description) { this.description = description; return this; }
        public Builder severity(ApiFindingSeverity severity) { this.severity = severity; return this; }
        public Builder confidence(ApiFindingConfidence confidence) { this.confidence = confidence; return this; }
        public Builder apiProjectId(Long apiProjectId) { this.apiProjectId = apiProjectId; return this; }
        public Builder httpMethod(HttpMethod httpMethod) { this.httpMethod = httpMethod; return this; }
        public Builder endpointPath(String endpointPath) { this.endpointPath = endpointPath; return this; }
        public Builder parameterOrField(String parameterOrField) { this.parameterOrField = parameterOrField; return this; }
        public Builder evidence(String evidence) { this.evidence = evidence; return this; }
        public Builder cweId(String cweId) { this.cweId = cweId; return this; }
        public Builder owaspCategory(OwaspApiCategory owaspCategory) { this.owaspCategory = owaspCategory; return this; }
        public Builder remediation(String remediation) { this.remediation = remediation; return this; }
        public Builder detectionTimestamp(Instant detectionTimestamp) { this.detectionTimestamp = detectionTimestamp; return this; }
        public Builder executionId(String executionId) { this.executionId = executionId; return this; }
        public Builder isConfirmed(boolean isConfirmed) { this.isConfirmed = isConfirmed; return this; }

        public ApiSecurityFinding build() {
            return new ApiSecurityFinding(
                    findingId,
                    ruleId,
                    title,
                    description,
                    severity,
                    confidence,
                    apiProjectId,
                    httpMethod,
                    endpointPath,
                    parameterOrField,
                    evidence,
                    cweId,
                    owaspCategory,
                    remediation,
                    detectionTimestamp,
                    executionId,
                    isConfirmed
            );
        }
    }
}

