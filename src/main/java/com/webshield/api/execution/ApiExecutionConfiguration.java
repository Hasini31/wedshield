package com.webshield.api.execution;

import java.io.Serializable;
import java.time.Duration;

/**
 * Configuration governing the execution of API security test cases.
 * Strictly enforces safe defaults, TLS certificate verification, and operational boundaries.
 */
public class ApiExecutionConfiguration implements Serializable {

    private Duration connectionTimeout = Duration.ofSeconds(5);
    private Duration requestTimeout = Duration.ofSeconds(10);
    private long maxResponseSizeBytes = 1024 * 1024; // 1 MB
    private int maxRedirects = 3;
    private int maxConcurrentRequests = 5;
    private double requestsPerSecond = 10.0;
    private int retryCount = 0;
    private final boolean tlsVerificationEnabled = true; // Non-negotiable TLS verification
    private String userAgent = "WebShield-ApiSecurityEngine/1.0 (Defensive Security Scanner)";
    private boolean allowLocalAddresses = false;
    private boolean allowUnsafeMethods = true; // Enabled for authorized API security scanning

    public ApiExecutionConfiguration() {
    }

    public static ApiExecutionConfiguration defaultConfig() {
        return new ApiExecutionConfiguration();
    }

    public static Builder builder() {
        return new Builder();
    }

    // Getters and Setters with defensive validation
    public Duration getConnectionTimeout() {
        return connectionTimeout;
    }

    public void setConnectionTimeout(Duration connectionTimeout) {
        if (connectionTimeout == null || connectionTimeout.isNegative() || connectionTimeout.isZero()) {
            throw new IllegalArgumentException("connectionTimeout must be a positive duration");
        }
        this.connectionTimeout = connectionTimeout;
    }

    public Duration getRequestTimeout() {
        return requestTimeout;
    }

    public void setRequestTimeout(Duration requestTimeout) {
        if (requestTimeout == null || requestTimeout.isNegative() || requestTimeout.isZero()) {
            throw new IllegalArgumentException("requestTimeout must be a positive duration");
        }
        this.requestTimeout = requestTimeout;
    }

    public long getMaxResponseSizeBytes() {
        return maxResponseSizeBytes;
    }

    public void setMaxResponseSizeBytes(long maxResponseSizeBytes) {
        if (maxResponseSizeBytes <= 0) {
            throw new IllegalArgumentException("maxResponseSizeBytes must be greater than 0");
        }
        this.maxResponseSizeBytes = maxResponseSizeBytes;
    }

    public int getMaxRedirects() {
        return maxRedirects;
    }

    public void setMaxRedirects(int maxRedirects) {
        if (maxRedirects < 0 || maxRedirects > 5) {
            throw new IllegalArgumentException("maxRedirects must be between 0 and 5");
        }
        this.maxRedirects = maxRedirects;
    }

    public int getMaxConcurrentRequests() {
        return maxConcurrentRequests;
    }

    public void setMaxConcurrentRequests(int maxConcurrentRequests) {
        if (maxConcurrentRequests < 1) {
            throw new IllegalArgumentException("maxConcurrentRequests must be at least 1");
        }
        this.maxConcurrentRequests = maxConcurrentRequests;
    }

    public double getRequestsPerSecond() {
        return requestsPerSecond;
    }

    public void setRequestsPerSecond(double requestsPerSecond) {
        if (requestsPerSecond <= 0.0) {
            throw new IllegalArgumentException("requestsPerSecond must be positive");
        }
        this.requestsPerSecond = requestsPerSecond;
    }

    public int getRetryCount() {
        return retryCount;
    }

    public void setRetryCount(int retryCount) {
        if (retryCount < 0 || retryCount > 3) {
            throw new IllegalArgumentException("retryCount must be between 0 and 3");
        }
        this.retryCount = retryCount;
    }

    public boolean isTlsVerificationEnabled() {
        return tlsVerificationEnabled;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            throw new IllegalArgumentException("userAgent cannot be null or blank");
        }
        this.userAgent = userAgent.trim();
    }

    public boolean isAllowLocalAddresses() {
        return allowLocalAddresses;
    }

    public void setAllowLocalAddresses(boolean allowLocalAddresses) {
        this.allowLocalAddresses = allowLocalAddresses;
    }

    public boolean isAllowUnsafeMethods() {
        return allowUnsafeMethods;
    }

    public void setAllowUnsafeMethods(boolean allowUnsafeMethods) {
        this.allowUnsafeMethods = allowUnsafeMethods;
    }

    public static class Builder {
        private final ApiExecutionConfiguration config = new ApiExecutionConfiguration();

        public Builder connectionTimeout(Duration timeout) {
            config.setConnectionTimeout(timeout);
            return this;
        }

        public Builder requestTimeout(Duration timeout) {
            config.setRequestTimeout(timeout);
            return this;
        }

        public Builder maxResponseSizeBytes(long maxBytes) {
            config.setMaxResponseSizeBytes(maxBytes);
            return this;
        }

        public Builder maxRedirects(int max) {
            config.setMaxRedirects(max);
            return this;
        }

        public Builder maxConcurrentRequests(int max) {
            config.setMaxConcurrentRequests(max);
            return this;
        }

        public Builder requestsPerSecond(double rps) {
            config.setRequestsPerSecond(rps);
            return this;
        }

        public Builder retryCount(int retries) {
            config.setRetryCount(retries);
            return this;
        }

        public Builder userAgent(String userAgent) {
            config.setUserAgent(userAgent);
            return this;
        }

        public Builder allowLocalAddresses(boolean allow) {
            config.setAllowLocalAddresses(allow);
            return this;
        }

        public Builder allowUnsafeMethods(boolean allow) {
            config.setAllowUnsafeMethods(allow);
            return this;
        }

        public ApiExecutionConfiguration build() {
            return config;
        }
    }
}

