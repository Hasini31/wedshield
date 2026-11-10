package com.webshield.api.parser;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.responses.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Resolves local OpenAPI and Swagger 2.0 `$ref` pointers with strict cycle detection,
 * recursion depth safeguards, and SSRF external-resource protection.
 */
public class SchemaResolver {

    private static final Logger log = LoggerFactory.getLogger(SchemaResolver.class);
    public static final int MAX_RECURSION_DEPTH = 30;

    private final OpenAPI openAPI;
    private final Set<String> activeRefStack = new HashSet<>();

    public SchemaResolver(OpenAPI openAPI) {
        this.openAPI = openAPI;
    }

    /**
     * Resolves a schema reference string into the raw Swagger/OpenAPI {@link Schema}.
     * Rejects remote/external URLs for security.
     *
     * @param ref reference string, e.g. {@code #/components/schemas/User} or {@code #/definitions/User}
     * @return referenced Schema object, or {@code null} if unresolvable or external
     */
    public Schema<?> resolveSchema(String ref) {
        if (ref == null || ref.isBlank()) {
            return null;
        }

        String normalizedRef = ref.trim();
        if (isExternalRef(normalizedRef)) {
            log.warn("Blocked external reference resolution for security: {}", normalizedRef);
            return null;
        }

        String schemaName = extractComponentName(normalizedRef);
        if (schemaName == null || openAPI == null) {
            return null;
        }

        Components components = openAPI.getComponents();
        if (components == null) {
            return null;
        }

        Map<String, Schema> schemas = components.getSchemas();
        if (schemas == null || schemas.isEmpty()) {
            return null;
        }

        // Direct lookup
        Schema<?> resolved = schemas.get(schemaName);
        if (resolved != null) {
            return resolved;
        }

        // Case-insensitive or unescaped lookup
        for (Map.Entry<String, Schema> entry : schemas.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(schemaName)) {
                return entry.getValue();
            }
        }

        return null;
    }

    /**
     * Resolves a parameter reference, e.g. {@code #/components/parameters/PageParam}.
     */
    public Parameter resolveParameter(String ref) {
        if (ref == null || isExternalRef(ref) || openAPI == null) {
            return null;
        }
        Components components = openAPI.getComponents();
        if (components == null || components.getParameters() == null) {
            return null;
        }
        String name = extractComponentName(ref);
        return components.getParameters().get(name);
    }

    /**
     * Resolves a request body reference, e.g. {@code #/components/requestBodies/UserBody}.
     */
    public RequestBody resolveRequestBody(String ref) {
        if (ref == null || isExternalRef(ref) || openAPI == null) {
            return null;
        }
        Components components = openAPI.getComponents();
        if (components == null || components.getRequestBodies() == null) {
            return null;
        }
        String name = extractComponentName(ref);
        return components.getRequestBodies().get(name);
    }

    /**
     * Resolves an API response reference, e.g. {@code #/components/responses/NotFound}.
     */
    public ApiResponse resolveResponse(String ref) {
        if (ref == null || isExternalRef(ref) || openAPI == null) {
            return null;
        }
        Components components = openAPI.getComponents();
        if (components == null || components.getResponses() == null) {
            return null;
        }
        String name = extractComponentName(ref);
        return components.getResponses().get(name);
    }

    /**
     * Checks if a reference is already being actively traversed along the current resolution branch.
     */
    public boolean isCircular(String ref) {
        if (ref == null) return false;
        return activeRefStack.contains(normalizeRef(ref));
    }

    /**
     * Pushes a reference onto the active resolution path.
     */
    public boolean pushRef(String ref) {
        if (ref == null) return false;
        return activeRefStack.add(normalizeRef(ref));
    }

    /**
     * Pops a reference off the active resolution path.
     */
    public void popRef(String ref) {
        if (ref != null) {
            activeRefStack.remove(normalizeRef(ref));
        }
    }

    /**
     * Extracts the target entity key from a pointer string.
     */
    public String extractComponentName(String ref) {
        if (ref == null) return null;
        String clean = ref.trim();
        int slashIdx = clean.lastIndexOf('/');
        if (slashIdx >= 0 && slashIdx < clean.length() - 1) {
            return clean.substring(slashIdx + 1);
        }
        if (clean.startsWith("#")) {
            return clean.substring(1);
        }
        return clean;
    }

    private boolean isExternalRef(String ref) {
        String lower = ref.toLowerCase(Locale.ROOT);
        return lower.startsWith("http://")
                || lower.startsWith("https://")
                || lower.startsWith("file://")
                || lower.startsWith("ftp://")
                || (!ref.startsWith("#") && (ref.contains("/") || ref.contains("\\")));
    }

    private String normalizeRef(String ref) {
        return ref.trim();
    }
}

