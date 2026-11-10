package com.webshield.api.parser;

import com.webshield.api.models.ApiEndpoint;
import com.webshield.api.models.OpenApiMetadata;
import com.webshield.api.models.ParsedApiSpecification;
import io.swagger.parser.OpenAPIParser;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.tags.Tag;
import io.swagger.v3.parser.core.models.ParseOptions;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Main parsing and endpoint extraction engine for OpenAPI 3.x and Swagger 2.0 specifications.
 * Enforces safe local-only parsing without automatic remote reference resolution.
 */
@Component
public class OpenApiParser {

    private static final Logger log = LoggerFactory.getLogger(OpenApiParser.class);

    public OpenApiParser() {
    }

    /**
     * Parses raw OpenAPI/Swagger JSON or YAML content into an immutable {@link ParsedApiSpecification}.
     *
     * @param rawSpec raw specification string
     * @return fully parsed specification with extracted endpoints and metadata
     * @throws OpenApiParseException if parsing fails or specification is invalid
     */
    public ParsedApiSpecification parse(String rawSpec) {
        if (rawSpec == null || rawSpec.isBlank()) {
            throw new OpenApiParseException("Specification content cannot be empty.");
        }

        ParseOptions options = new ParseOptions();
        // Defensive security: do not resolve external URLs or fetch remote hosts
        options.setResolve(false);
        options.setResolveFully(false);

        SwaggerParseResult parseResult;
        try {
            parseResult = new OpenAPIParser().readContents(rawSpec, null, options);
        } catch (Exception e) {
            log.error("Unhandled exception during OpenAPI parsing", e);
            throw new OpenApiParseException("Failed to parse specification: " + e.getMessage(), e);
        }

        if (parseResult == null || parseResult.getOpenAPI() == null) {
            List<String> messages = (parseResult != null && parseResult.getMessages() != null)
                    ? parseResult.getMessages()
                    : List.of("Parser produced null OpenAPI model.");
            throw new OpenApiParseException("Failed to parse OpenAPI/Swagger specification.", messages);
        }

        OpenAPI openAPI = parseResult.getOpenAPI();

        // Metadata extraction
        OpenApiMetadata metadata = extractMetadata(openAPI);

        // Resolvers and extractors
        SchemaResolver resolver = new SchemaResolver(openAPI);
        SchemaExtractor schemaExtractor = new SchemaExtractor(resolver);
        EndpointExtractor endpointExtractor = new EndpointExtractor(openAPI, resolver, schemaExtractor);

        List<ApiEndpoint> endpoints = endpointExtractor.extractEndpoints();

        List<String> warnings = parseResult.getMessages() != null
                ? new ArrayList<>(parseResult.getMessages())
                : new ArrayList<>();

        log.info("Successfully parsed API specification: title='{}', version='{}', endpoints={}",
                metadata.getTitle(), metadata.getVersion(), endpoints.size());

        return new ParsedApiSpecification(
                metadata,
                endpoints,
                warnings,
                new ArrayList<>(),
                rawSpec
        );
    }

    /**
     * Parses a specification from a local file.
     */
    public ParsedApiSpecification parse(File file) {
        if (file == null) {
            throw new OpenApiParseException("Specification file cannot be null.");
        }
        if (!file.exists() || !file.isFile()) {
            throw new OpenApiParseException("Specification file does not exist: " + file.getPath());
        }
        try {
            String content = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            return parse(content);
        } catch (IOException e) {
            throw new OpenApiParseException("Failed to read specification file: " + e.getMessage(), e);
        }
    }

    /**
     * Parses a specification from a {@link Path}.
     */
    public ParsedApiSpecification parse(Path path) {
        if (path == null) {
            throw new OpenApiParseException("Specification path cannot be null.");
        }
        return parse(path.toFile());
    }

    private OpenApiMetadata extractMetadata(OpenAPI openAPI) {
        OpenApiMetadata meta = new OpenApiMetadata();

        if (openAPI.getInfo() != null) {
            Info info = openAPI.getInfo();
            if (info.getTitle() != null) meta.setTitle(info.getTitle());
            if (info.getVersion() != null) meta.setVersion(info.getVersion());
            if (info.getDescription() != null) meta.setDescription(info.getDescription());
        }

        if (openAPI.getOpenapi() != null) {
            meta.setOpenApiVersion(openAPI.getOpenapi());
        }

        if (openAPI.getServers() != null) {
            for (Server s : openAPI.getServers()) {
                if (s.getUrl() != null && !s.getUrl().isBlank()) {
                    meta.addServer(s.getUrl());
                }
            }
        }

        if (openAPI.getTags() != null) {
            for (Tag t : openAPI.getTags()) {
                if (t.getName() != null && !t.getName().isBlank()) {
                    meta.addTag(t.getName());
                }
            }
        }

        return meta;
    }
}

