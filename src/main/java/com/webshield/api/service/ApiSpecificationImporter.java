package com.webshield.api.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webshield.api.models.SpecFormat;
import com.webshield.api.models.SpecType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.util.*;

/**
 * Handles validation, format detection, and ingestion of OpenAPI/Swagger specifications
 * from file uploads or remote URLs.
 */
@Component
public class ApiSpecificationImporter {

    private static final Logger log = LoggerFactory.getLogger(ApiSpecificationImporter.class);

    public static final long MAX_SPEC_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB
    private static final Set<String> HTTP_METHODS = Set.of(
            "get", "post", "put", "delete", "patch", "options", "head", "trace"
    );

    private final ObjectMapper objectMapper;

    public ApiSpecificationImporter() {
        this(new ObjectMapper());
    }

    public ApiSpecificationImporter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
    }

    /**
     * Inspects and validates raw specification text (JSON or YAML).
     *
     * @param rawSpec raw specification string
     * @return inspection metadata containing format, standard version, and endpoint count
     * @throws IllegalArgumentException if the specification is empty, oversized, malformed,
     *                                  or missing OpenAPI/Swagger identifiers
     */
    public SpecInspectionResult validateAndInspect(String rawSpec) {
        if (rawSpec == null || rawSpec.isBlank()) {
            throw new IllegalArgumentException("Specification content cannot be empty.");
        }

        byte[] rawBytes = rawSpec.getBytes(StandardCharsets.UTF_8);
        if (rawBytes.length > MAX_SPEC_SIZE_BYTES) {
            throw new IllegalArgumentException(String.format(
                    "Specification size (%d bytes) exceeds maximum permitted limit of %d bytes (5 MB).",
                    rawBytes.length, MAX_SPEC_SIZE_BYTES
            ));
        }

        String trimmed = rawSpec.trim();
        SpecFormat format = detectFormat(trimmed);
        JsonNode rootNode = parseToTree(trimmed, format);

        if (!rootNode.isObject()) {
            throw new IllegalArgumentException("Invalid specification: root structure must be a JSON/YAML object.");
        }

        SpecType specType = detectSpecType(rootNode);

        String title = "Untitled API";
        String version = "1.0.0";
        if (rootNode.has("info") && rootNode.get("info").isObject()) {
            JsonNode infoNode = rootNode.get("info");
            if (infoNode.hasNonNull("title")) {
                title = infoNode.get("title").asText();
            }
            if (infoNode.hasNonNull("version")) {
                version = infoNode.get("version").asText();
            }
        }

        int endpointsCount = countEndpoints(rootNode);

        log.info("Specification inspected successfully: type={}, format={}, endpoints={}, title='{}', version='{}'",
                specType, format, endpointsCount, title, version);

        return new SpecInspectionResult(specType, format, endpointsCount, title, version);
    }

    /**
     * Reads and validates specification content from a local file.
     *
     * @param file target file
     * @return raw UTF-8 string content
     */
    public String readFromFile(File file) {
        if (file == null) {
            throw new IllegalArgumentException("Specification file must not be null.");
        }
        if (!file.exists() || !file.isFile()) {
            throw new IllegalArgumentException("Specification file does not exist: " + file.getPath());
        }
        if (!file.canRead()) {
            throw new IllegalArgumentException("Specification file is not readable: " + file.getPath());
        }
        if (file.length() > MAX_SPEC_SIZE_BYTES) {
            throw new IllegalArgumentException(String.format(
                    "Specification file (%d bytes) exceeds maximum permitted limit of %d bytes (5 MB).",
                    file.length(), MAX_SPEC_SIZE_BYTES
            ));
        }

        try {
            return Files.readString(file.toPath(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.error("Failed to read specification file: {}", file.getAbsolutePath(), e);
            throw new IllegalArgumentException("Failed to read specification file: " + e.getMessage(), e);
        }
    }

    /**
     * Fetches and validates specification content from an HTTP/HTTPS URL with SSRF protection.
     *
     * @param urlString target URL
     * @return raw downloaded string content
     */
    public String fetchFromUrl(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            throw new IllegalArgumentException("Specification URL cannot be empty.");
        }

        URI uri;
        try {
            uri = URI.create(urlString.trim());
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid specification URL format: " + urlString, e);
        }

        String scheme = uri.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
            throw new IllegalArgumentException("Specification URL must use HTTP or HTTPS protocol: " + urlString);
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Specification URL contains invalid host: " + urlString);
        }

        validateHostSafety(host);

        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .timeout(Duration.ofSeconds(15))
                    .header("Accept", "application/json, application/yaml, application/x-yaml, text/yaml, text/plain, */*")
                    .header("User-Agent", "WebShield-Security-Scanner/2.0")
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IllegalArgumentException(String.format(
                        "Remote server returned HTTP status %d when fetching specification.", response.statusCode()
                ));
            }

            String body = response.body();
            if (body == null || body.isBlank()) {
                throw new IllegalArgumentException("Remote server returned empty specification content.");
            }

            if (body.getBytes(StandardCharsets.UTF_8).length > MAX_SPEC_SIZE_BYTES) {
                throw new IllegalArgumentException("Remote specification content exceeds maximum size of 5 MB.");
            }

            return body;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to fetch specification from URL: {}", urlString, e);
            throw new IllegalArgumentException("Failed to fetch specification from URL: " + e.getMessage(), e);
        }
    }

    /**
     * Determines whether content is JSON or YAML based on prefix characteristics.
     */
    public SpecFormat detectFormat(String trimmed) {
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            return SpecFormat.JSON;
        }
        return SpecFormat.YAML;
    }

    /**
     * Parses specification text into a Jackson JsonNode tree.
     */
    private JsonNode parseToTree(String content, SpecFormat format) {
        if (format == SpecFormat.JSON) {
            try {
                return objectMapper.readTree(content);
            } catch (JsonProcessingException e) {
                // Try fallback to YAML in case of JSON parse failure
                try {
                    return parseYamlToTree(content);
                } catch (Exception ignored) {
                    throw new IllegalArgumentException("Malformed JSON specification: " + e.getOriginalMessage(), e);
                }
            }
        } else {
            try {
                return parseYamlToTree(content);
            } catch (Exception e) {
                // Try fallback to JSON in case of YAML parse failure
                try {
                    return objectMapper.readTree(content);
                } catch (Exception ignored) {
                    throw new IllegalArgumentException("Malformed YAML specification: " + e.getMessage(), e);
                }
            }
        }
    }

    private JsonNode parseYamlToTree(String yamlContent) {
        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setCodePointLimit((int) MAX_SPEC_SIZE_BYTES);
        Yaml yaml = new Yaml(new SafeConstructor(loaderOptions));
        Object loaded = yaml.load(yamlContent);
        if (loaded == null) {
            throw new IllegalArgumentException("YAML document is empty or null.");
        }
        return objectMapper.valueToTree(loaded);
    }

    /**
     * Detects whether the specification is OpenAPI 3.x or Swagger 2.0.
     */
    private SpecType detectSpecType(JsonNode rootNode) {
        if (rootNode.hasNonNull("openapi")) {
            String openapiVer = rootNode.get("openapi").asText().trim();
            if (openapiVer.startsWith("3.")) {
                return SpecType.OPENAPI_3;
            }
            return SpecType.OPENAPI_3;
        }
        if (rootNode.hasNonNull("swagger")) {
            String swaggerVer = rootNode.get("swagger").asText().trim();
            if (swaggerVer.startsWith("2.")) {
                return SpecType.SWAGGER_2;
            }
            return SpecType.SWAGGER_2;
        }

        throw new IllegalArgumentException(
                "Invalid API specification: missing required 'openapi' or 'swagger' root field."
        );
    }

    /**
     * Counts the total number of distinct endpoint operations (path + method pairs).
     */
    private int countEndpoints(JsonNode rootNode) {
        if (!rootNode.has("paths") || !rootNode.get("paths").isObject()) {
            return 0;
        }

        int count = 0;
        JsonNode paths = rootNode.get("paths");
        Iterator<Map.Entry<String, JsonNode>> pathIterator = paths.fields();
        while (pathIterator.hasNext()) {
            Map.Entry<String, JsonNode> pathEntry = pathIterator.next();
            JsonNode itemNode = pathEntry.getValue();
            if (itemNode != null && itemNode.isObject()) {
                Iterator<String> fieldNames = itemNode.fieldNames();
                while (fieldNames.hasNext()) {
                    String method = fieldNames.next().toLowerCase(Locale.ROOT);
                    if (HTTP_METHODS.contains(method)) {
                        count++;
                    }
                }
            }
        }
        return count;
    }

    /**
     * Rejects private, loopback, or cloud-metadata destinations to prevent SSRF vulnerabilities.
     */
    private void validateHostSafety(String host) {
        String lowerHost = host.toLowerCase(Locale.ROOT).trim();
        if (lowerHost.equals("localhost")
                || lowerHost.equals("127.0.0.1")
                || lowerHost.equals("::1")
                || lowerHost.equals("169.254.169.254")
                || lowerHost.equals("metadata.google.internal")
                || lowerHost.equals("0.0.0.0")) {
            throw new IllegalArgumentException("Specification URL host is blocked for security (loopback or cloud metadata): " + host);
        }

        try {
            InetAddress address = InetAddress.getByName(host);
            if (address.isLoopbackAddress() || address.isLinkLocalAddress()) {
                throw new IllegalArgumentException("Specification URL resolves to restricted network address: " + host);
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception ignored) {
            // DNS resolution failure will be handled by HttpClient.send
        }
    }
}

