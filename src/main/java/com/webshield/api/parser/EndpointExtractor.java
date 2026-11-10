package com.webshield.api.parser;

import com.webshield.api.models.*;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.headers.Header;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Extracts and maps OpenAPI Operations and PathItems into strongly-typed {@link ApiEndpoint} models.
 */
public class EndpointExtractor {

    private static final Logger log = LoggerFactory.getLogger(EndpointExtractor.class);

    private final OpenAPI openAPI;
    private final SchemaResolver resolver;
    private final SchemaExtractor schemaExtractor;

    public EndpointExtractor(OpenAPI openAPI, SchemaResolver resolver, SchemaExtractor schemaExtractor) {
        this.openAPI = openAPI;
        this.resolver = resolver;
        this.schemaExtractor = schemaExtractor;
    }

    /**
     * Extracts all endpoints across all paths and supported HTTP methods.
     */
    public List<ApiEndpoint> extractEndpoints() {
        if (openAPI == null || openAPI.getPaths() == null || openAPI.getPaths().isEmpty()) {
            return List.of();
        }

        List<ApiEndpoint> endpoints = new ArrayList<>();

        for (Map.Entry<String, PathItem> pathEntry : openAPI.getPaths().entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();
            if (pathItem == null) continue;

            List<Parameter> pathLevelParameters = pathItem.getParameters() != null
                    ? pathItem.getParameters()
                    : List.of();

            extractOperation(path, HttpMethod.GET, pathItem.getGet(), pathLevelParameters, endpoints);
            extractOperation(path, HttpMethod.POST, pathItem.getPost(), pathLevelParameters, endpoints);
            extractOperation(path, HttpMethod.PUT, pathItem.getPut(), pathLevelParameters, endpoints);
            extractOperation(path, HttpMethod.DELETE, pathItem.getDelete(), pathLevelParameters, endpoints);
            extractOperation(path, HttpMethod.PATCH, pathItem.getPatch(), pathLevelParameters, endpoints);
            extractOperation(path, HttpMethod.HEAD, pathItem.getHead(), pathLevelParameters, endpoints);
            extractOperation(path, HttpMethod.OPTIONS, pathItem.getOptions(), pathLevelParameters, endpoints);
            extractOperation(path, HttpMethod.TRACE, pathItem.getTrace(), pathLevelParameters, endpoints);
        }

        return Collections.unmodifiableList(endpoints);
    }

    private void extractOperation(String path, HttpMethod method, Operation operation,
                                  List<Parameter> pathLevelParams, List<ApiEndpoint> sink) {
        if (operation == null) {
            return;
        }

        ApiEndpoint endpoint = new ApiEndpoint(path, method);
        endpoint.setOperationId(operation.getOperationId());
        endpoint.setSummary(operation.getSummary());
        endpoint.setDescription(operation.getDescription());
        if (operation.getDeprecated() != null) {
            endpoint.setDeprecated(operation.getDeprecated());
        }

        // Tags
        if (operation.getTags() != null) {
            for (String tag : operation.getTags()) {
                endpoint.addTag(tag);
            }
        }

        // Merge Parameters (operation parameters override path-level parameters with same name & location)
        Map<String, Parameter> mergedParams = new LinkedHashMap<>();
        for (Parameter p : pathLevelParams) {
            Parameter resolved = resolveParameter(p);
            if (resolved != null && resolved.getName() != null) {
                String key = (resolved.getIn() != null ? resolved.getIn() : "query") + ":" + resolved.getName().toLowerCase(Locale.ROOT);
                mergedParams.put(key, resolved);
            }
        }
        if (operation.getParameters() != null) {
            for (Parameter p : operation.getParameters()) {
                Parameter resolved = resolveParameter(p);
                if (resolved != null && resolved.getName() != null) {
                    String key = (resolved.getIn() != null ? resolved.getIn() : "query") + ":" + resolved.getName().toLowerCase(Locale.ROOT);
                    mergedParams.put(key, resolved);
                }
            }
        }

        for (Parameter param : mergedParams.values()) {
            ApiParameter apiParam = mapParameter(param);
            endpoint.addParameter(apiParam);
        }

        // Request Body
        if (operation.getRequestBody() != null) {
            RequestBody rawBody = resolveRequestBody(operation.getRequestBody());
            if (rawBody != null) {
                ApiRequestBody apiBody = mapRequestBody(rawBody);
                endpoint.setRequestBody(apiBody);
            }
        }

        // Responses
        if (operation.getResponses() != null) {
            mapResponses(operation.getResponses(), endpoint);
        }

        // Security Requirements
        mapSecurity(operation, endpoint);

        sink.add(endpoint);
    }

    private Parameter resolveParameter(Parameter p) {
        if (p == null) return null;
        if (p.get$ref() != null && !p.get$ref().isBlank()) {
            Parameter resolved = resolver.resolveParameter(p.get$ref());
            return resolved != null ? resolved : p;
        }
        return p;
    }

    private RequestBody resolveRequestBody(RequestBody body) {
        if (body == null) return null;
        if (body.get$ref() != null && !body.get$ref().isBlank()) {
            RequestBody resolved = resolver.resolveRequestBody(body.get$ref());
            return resolved != null ? resolved : body;
        }
        return body;
    }

    private ApiResponse resolveResponse(ApiResponse resp) {
        if (resp == null) return null;
        if (resp.get$ref() != null && !resp.get$ref().isBlank()) {
            ApiResponse resolved = resolver.resolveResponse(resp.get$ref());
            return resolved != null ? resolved : resp;
        }
        return resp;
    }

    private ApiParameter mapParameter(Parameter p) {
        ParameterLocation location = ParameterLocation.fromString(p.getIn());
        boolean required = Boolean.TRUE.equals(p.getRequired()) || location == ParameterLocation.PATH;
        boolean deprecated = Boolean.TRUE.equals(p.getDeprecated());

        ApiSchema schema = p.getSchema() != null
                ? schemaExtractor.extractSchema(p.getSchema())
                : ApiSchema.ofType(SchemaType.STRING);

        return new ApiParameter(
                p.getName(),
                location,
                p.getDescription(),
                required,
                deprecated,
                schema,
                p.getExample()
        );
    }

    private ApiRequestBody mapRequestBody(RequestBody body) {
        ApiRequestBody apiBody = new ApiRequestBody(
                body.getDescription(),
                Boolean.TRUE.equals(body.getRequired())
        );

        Content content = body.getContent();
        if (content != null) {
            for (Map.Entry<String, MediaType> entry : content.entrySet()) {
                String mediaTypeKey = entry.getKey();
                MediaType mediaType = entry.getValue();
                ApiSchema schema = (mediaType != null && mediaType.getSchema() != null)
                        ? schemaExtractor.extractSchema(mediaType.getSchema())
                        : ApiSchema.ofType(SchemaType.ANY);
                apiBody.addContentType(mediaTypeKey, schema);
            }
        }

        return apiBody;
    }

    private void mapResponses(ApiResponses responses, ApiEndpoint endpoint) {
        for (Map.Entry<String, ApiResponse> entry : responses.entrySet()) {
            String statusCode = entry.getKey();
            ApiResponse rawResponse = resolveResponse(entry.getValue());
            if (rawResponse == null) continue;

            ApiResponseSchema apiResp = new ApiResponseSchema(statusCode, rawResponse.getDescription());

            // Media types
            Content content = rawResponse.getContent();
            if (content != null) {
                for (Map.Entry<String, MediaType> mediaEntry : content.entrySet()) {
                    String mediaTypeKey = mediaEntry.getKey();
                    MediaType mediaType = mediaEntry.getValue();
                    ApiSchema schema = (mediaType != null && mediaType.getSchema() != null)
                            ? schemaExtractor.extractSchema(mediaType.getSchema())
                            : ApiSchema.ofType(SchemaType.ANY);
                    apiResp.addContentType(mediaTypeKey, schema);
                }
            }

            // Headers
            Map<String, Header> headers = rawResponse.getHeaders();
            if (headers != null) {
                for (Map.Entry<String, Header> headerEntry : headers.entrySet()) {
                    String headerName = headerEntry.getKey();
                    Header rawHeader = headerEntry.getValue();
                    if (rawHeader != null) {
                        ApiSchema headerSchema = rawHeader.getSchema() != null
                                ? schemaExtractor.extractSchema(rawHeader.getSchema())
                                : ApiSchema.ofType(SchemaType.STRING);
                        ApiParameter headerParam = new ApiParameter(
                                headerName,
                                ParameterLocation.HEADER,
                                rawHeader.getDescription(),
                                Boolean.TRUE.equals(rawHeader.getRequired()),
                                Boolean.TRUE.equals(rawHeader.getDeprecated()),
                                headerSchema,
                                rawHeader.getExample()
                        );
                        apiResp.addHeader(headerName, headerParam);
                    }
                }
            }

            endpoint.addResponse(statusCode, apiResp);
        }
    }

    private void mapSecurity(Operation operation, ApiEndpoint endpoint) {
        List<SecurityRequirement> securityList = operation.getSecurity();
        if (securityList == null && openAPI.getSecurity() != null) {
            securityList = openAPI.getSecurity();
        }

        if (securityList == null || securityList.isEmpty()) {
            return;
        }

        Map<String, SecurityScheme> schemesMap = (openAPI.getComponents() != null && openAPI.getComponents().getSecuritySchemes() != null)
                ? openAPI.getComponents().getSecuritySchemes()
                : Collections.emptyMap();

        for (SecurityRequirement secReq : securityList) {
            for (Map.Entry<String, List<String>> schemeEntry : secReq.entrySet()) {
                String schemeName = schemeEntry.getKey();
                List<String> scopes = schemeEntry.getValue();

                SecurityScheme scheme = schemesMap.get(schemeName);
                if (scheme != null) {
                    ApiSecurityRequirement apiSec = new ApiSecurityRequirement(
                            schemeName,
                            scheme.getType() != null ? scheme.getType().toString().toLowerCase(Locale.ROOT) : "http",
                            scheme.getScheme(),
                            scheme.getBearerFormat(),
                            scheme.getIn() != null ? scheme.getIn().toString().toLowerCase(Locale.ROOT) : null,
                            scheme.getName(),
                            scopes
                    );
                    endpoint.addSecurityRequirement(apiSec);
                } else {
                    // Fallback when security scheme is declared in security requirement without components definition
                    ApiSecurityRequirement genericSec = new ApiSecurityRequirement(
                            schemeName,
                            "http",
                            null,
                            null,
                            null,
                            null,
                            scopes
                    );
                    endpoint.addSecurityRequirement(genericSec);
                }
            }
        }
    }
}

