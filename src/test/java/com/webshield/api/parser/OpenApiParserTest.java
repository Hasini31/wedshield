package com.webshield.api.parser;

import com.webshield.api.models.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Module B: OpenApiParser & Endpoint Model Extractor Tests")
class OpenApiParserTest {

    private OpenApiParser parser;

    @BeforeEach
    void setUp() {
        parser = new OpenApiParser();
    }

    @Test
    @DisplayName("1. Simple OpenAPI specification parsing")
    void testSimpleOpenApiParsing() {
        String yaml = """
                openapi: 3.0.0
                info:
                  title: Ping API
                  version: 1.0.0
                  description: Simple ping service
                paths:
                  /ping:
                    get:
                      summary: Check status
                      responses:
                        '200':
                          description: OK response
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        assertNotNull(parsed);
        assertEquals("Ping API", parsed.getMetadata().getTitle());
        assertEquals("1.0.0", parsed.getMetadata().getVersion());
        assertEquals("3.0.0", parsed.getMetadata().getOpenApiVersion());
        assertEquals(1, parsed.getEndpointsCount());

        ApiEndpoint ep = parsed.getEndpoints().get(0);
        assertEquals("/ping", ep.getPath());
        assertEquals(HttpMethod.GET, ep.getMethod());
        assertEquals("Check status", ep.getSummary());
        assertTrue(ep.getResponses().containsKey("200"));
    }

    @Test
    @DisplayName("2. Multiple endpoints extraction")
    void testMultipleEndpointsExtraction() {
        String json = """
                {
                  "openapi": "3.0.2",
                  "info": { "title": "Store API", "version": "1.0" },
                  "paths": {
                    "/users": { "get": {} },
                    "/products": { "get": {} },
                    "/orders": { "get": {} }
                  }
                }
                """;

        ParsedApiSpecification parsed = parser.parse(json);
        assertEquals(3, parsed.getEndpointsCount());
        assertTrue(parsed.findEndpoint("/users", HttpMethod.GET).isPresent());
        assertTrue(parsed.findEndpoint("/products", HttpMethod.GET).isPresent());
        assertTrue(parsed.findEndpoint("/orders", HttpMethod.GET).isPresent());
    }

    @Test
    @DisplayName("3. Multiple HTTP methods on same path (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)")
    void testMultipleHttpMethods() {
        String yaml = """
                openapi: 3.0.0
                info:
                  title: Restful Entity API
                  version: 1.0.0
                paths:
                  /items/{id}:
                    get: { summary: Get item }
                    post: { summary: Create item }
                    put: { summary: Replace item }
                    patch: { summary: Modify item }
                    delete: { summary: Remove item }
                    head: { summary: Query item headers }
                    options: { summary: Supported operations }
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        assertEquals(7, parsed.getEndpointsCount());
        assertTrue(parsed.findEndpoint("/items/{id}", HttpMethod.GET).isPresent());
        assertTrue(parsed.findEndpoint("/items/{id}", HttpMethod.POST).isPresent());
        assertTrue(parsed.findEndpoint("/items/{id}", HttpMethod.PUT).isPresent());
        assertTrue(parsed.findEndpoint("/items/{id}", HttpMethod.PATCH).isPresent());
        assertTrue(parsed.findEndpoint("/items/{id}", HttpMethod.DELETE).isPresent());
        assertTrue(parsed.findEndpoint("/items/{id}", HttpMethod.HEAD).isPresent());
        assertTrue(parsed.findEndpoint("/items/{id}", HttpMethod.OPTIONS).isPresent());
    }

    @Test
    @DisplayName("4. Path parameters extraction with type and required constraints")
    void testPathParameters() {
        String yaml = """
                openapi: 3.0.0
                info:
                  title: Users API
                  version: 1.0.0
                paths:
                  /orgs/{orgId}/users/{userId}:
                    get:
                      parameters:
                        - name: orgId
                          in: path
                          required: true
                          schema:
                            type: integer
                            format: int64
                        - name: userId
                          in: path
                          schema:
                            type: string
                            format: uuid
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        ApiEndpoint endpoint = parsed.getEndpoints().get(0);
        List<ApiParameter> pathParams = endpoint.getPathParameters();
        assertEquals(2, pathParams.size());

        ApiParameter orgParam = endpoint.getParameter("orgId", ParameterLocation.PATH).orElseThrow();
        assertTrue(orgParam.isRequired(), "Path parameters must always be required");
        assertEquals(SchemaType.INTEGER, orgParam.getSchema().getType());
        assertEquals("int64", orgParam.getSchema().getFormat());

        ApiParameter userParam = endpoint.getParameter("userId", ParameterLocation.PATH).orElseThrow();
        assertTrue(userParam.isRequired());
        assertEquals(SchemaType.STRING, userParam.getSchema().getType());
        assertEquals("uuid", userParam.getSchema().getFormat());
    }

    @Test
    @DisplayName("5. Query parameters extraction with required flag and defaults")
    void testQueryParameters() {
        String yaml = """
                openapi: 3.0.0
                info:
                  title: Search API
                  version: 1.0.0
                paths:
                  /search:
                    get:
                      parameters:
                        - name: q
                          in: query
                          required: true
                          schema:
                            type: string
                        - name: limit
                          in: query
                          required: false
                          schema:
                            type: integer
                            default: 20
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        ApiEndpoint endpoint = parsed.getEndpoints().get(0);
        List<ApiParameter> queryParams = endpoint.getQueryParameters();
        assertEquals(2, queryParams.size());

        ApiParameter q = endpoint.getParameter("q", ParameterLocation.QUERY).orElseThrow();
        assertTrue(q.isRequired());

        ApiParameter limit = endpoint.getParameter("limit", ParameterLocation.QUERY).orElseThrow();
        assertFalse(limit.isRequired());
        assertEquals(20, limit.getSchema().getDefaultValue());
    }

    @Test
    @DisplayName("6. Header and Cookie parameters extraction")
    void testHeaderAndCookieParameters() {
        String yaml = """
                openapi: 3.0.0
                info:
                  title: Auth API
                  version: 1.0.0
                paths:
                  /profile:
                    get:
                      parameters:
                        - name: X-Client-Version
                          in: header
                          required: true
                          schema:
                            type: string
                        - name: session_id
                          in: cookie
                          required: false
                          schema:
                            type: string
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        ApiEndpoint endpoint = parsed.getEndpoints().get(0);

        List<ApiParameter> headers = endpoint.getHeaderParameters();
        assertEquals(1, headers.size());
        assertEquals("X-Client-Version", headers.get(0).getName());
        assertTrue(headers.get(0).isRequired());

        List<ApiParameter> cookies = endpoint.getCookieParameters();
        assertEquals(1, cookies.size());
        assertEquals("session_id", cookies.get(0).getName());
    }

    @Test
    @DisplayName("7. Request body extraction across multiple content types")
    void testRequestBodyExtraction() {
        String yaml = """
                openapi: 3.0.0
                info:
                  title: Media API
                  version: 1.0.0
                paths:
                  /upload:
                    post:
                      requestBody:
                        required: true
                        description: Upload payload
                        content:
                          application/json:
                            schema:
                              type: object
                              properties:
                                filename: { type: string }
                          multipart/form-data:
                            schema:
                              type: object
                              properties:
                                file: { type: string, format: binary }
                      responses:
                        '201': { description: Created }
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        ApiEndpoint endpoint = parsed.getEndpoints().get(0);
        assertTrue(endpoint.hasRequestBody());
        ApiRequestBody body = endpoint.getRequestBody();
        assertTrue(body.isRequired());
        assertEquals(2, body.getContentTypes().size());
        assertTrue(body.getContentTypes().contains("application/json"));
        assertTrue(body.getContentTypes().contains("multipart/form-data"));

        ApiSchema jsonSchema = body.getJsonSchema();
        assertNotNull(jsonSchema);
        assertEquals(SchemaType.OBJECT, jsonSchema.getType());
        assertTrue(jsonSchema.getProperties().containsKey("filename"));
    }

    @Test
    @DisplayName("8. Nested JSON schema extraction")
    void testNestedJsonSchema() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Customer API, version: 1.0 }
                paths:
                  /customers:
                    post:
                      requestBody:
                        content:
                          application/json:
                            schema:
                              type: object
                              properties:
                                name: { type: string }
                                address:
                                  type: object
                                  properties:
                                    city: { type: string }
                                    geo:
                                      type: object
                                      properties:
                                        lat: { type: number }
                                        lng: { type: number }
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        ApiSchema rootSchema = parsed.getEndpoints().get(0).getRequestBody().getJsonSchema();
        assertEquals(SchemaType.OBJECT, rootSchema.getType());

        ApiSchema addressSchema = rootSchema.getProperty("address");
        assertNotNull(addressSchema);
        assertEquals(SchemaType.OBJECT, addressSchema.getType());

        ApiSchema geoSchema = addressSchema.getProperty("geo");
        assertNotNull(geoSchema);
        assertEquals(SchemaType.OBJECT, geoSchema.getType());
        assertEquals(SchemaType.NUMBER, geoSchema.getProperty("lat").getType());
    }

    @Test
    @DisplayName("9. Arrays and nested objects extraction with item constraints")
    void testArrayConstraints() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Batch API, version: 1.0 }
                paths:
                  /batch:
                    post:
                      requestBody:
                        content:
                          application/json:
                            schema:
                              type: array
                              minItems: 1
                              maxItems: 50
                              uniqueItems: true
                              items:
                                type: object
                                properties:
                                  actionId: { type: string }
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        ApiSchema schema = parsed.getEndpoints().get(0).getRequestBody().getJsonSchema();
        assertEquals(SchemaType.ARRAY, schema.getType());
        assertEquals(1, schema.getMinItems());
        assertEquals(50, schema.getMaxItems());
        assertTrue(schema.isUniqueItems());

        ApiSchema itemsSchema = schema.getItems();
        assertNotNull(itemsSchema);
        assertEquals(SchemaType.OBJECT, itemsSchema.getType());
        assertTrue(itemsSchema.getProperties().containsKey("actionId"));
    }

    @Test
    @DisplayName("10. Required and optional object fields preservation")
    void testRequiredAndOptionalProperties() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Account API, version: 1.0 }
                paths:
                  /accounts:
                    post:
                      requestBody:
                        content:
                          application/json:
                            schema:
                              type: object
                              required:
                                - username
                                - email
                              properties:
                                username: { type: string }
                                email: { type: string }
                                bio: { type: string }
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        ApiSchema schema = parsed.getEndpoints().get(0).getRequestBody().getJsonSchema();
        assertTrue(schema.isRequired("username"));
        assertTrue(schema.isRequired("email"));
        assertFalse(schema.isRequired("bio"));
        assertEquals(2, schema.getRequiredProperties().size());
    }

    @Test
    @DisplayName("11. Enum extraction for strings and numbers")
    void testEnumExtraction() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Orders API, version: 1.0 }
                paths:
                  /orders:
                    post:
                      requestBody:
                        content:
                          application/json:
                            schema:
                              type: object
                              properties:
                                status:
                                  type: string
                                  enum: [PENDING, PROCESSING, SHIPPED, DELIVERED, CANCELLED]
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        ApiSchema schema = parsed.getEndpoints().get(0).getRequestBody().getJsonSchema();
        ApiSchema statusSchema = schema.getProperty("status");
        assertNotNull(statusSchema);
        List<String> enums = statusSchema.getEnumValues();
        assertEquals(5, enums.size());
        assertTrue(enums.contains("PENDING"));
        assertTrue(enums.contains("SHIPPED"));
    }

    @Test
    @DisplayName("12. Minimum and maximum numeric constraints")
    void testNumericConstraints() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Pricing API, version: 1.0 }
                paths:
                  /pricing:
                    post:
                      requestBody:
                        content:
                          application/json:
                            schema:
                              type: object
                              properties:
                                price:
                                  type: number
                                  minimum: 0.01
                                  maximum: 9999.99
                                  exclusiveMinimum: true
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        ApiSchema schema = parsed.getEndpoints().get(0).getRequestBody().getJsonSchema();
        ApiSchema price = schema.getProperty("price");
        assertEquals(new BigDecimal("0.01"), price.getMinimum());
        assertEquals(new BigDecimal("9999.99"), price.getMaximum());
        assertTrue(price.isExclusiveMinimum());
    }

    @Test
    @DisplayName("13. Regex patterns, string lengths, and formats extraction")
    void testStringConstraintsAndFormats() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Validation API, version: 1.0 }
                paths:
                  /validate:
                    post:
                      requestBody:
                        content:
                          application/json:
                            schema:
                              type: object
                              properties:
                                phone:
                                  type: string
                                  pattern: '^\\+?[1-9]\\d{1,14}$'
                                  minLength: 5
                                  maxLength: 15
                                email:
                                  type: string
                                  format: email
                      responses:
                        '200': { description: OK }
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        ApiSchema schema = parsed.getEndpoints().get(0).getRequestBody().getJsonSchema();
        ApiSchema phone = schema.getProperty("phone");
        assertEquals("^\\+?[1-9]\\d{1,14}$", phone.getPattern());
        assertEquals(5, phone.getMinLength());
        assertEquals(15, phone.getMaxLength());

        ApiSchema email = schema.getProperty("email");
        assertEquals("email", email.getFormat());
    }

    @Test
    @DisplayName("14. Local $ref reference resolution")
    void testLocalRefResolution() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Ref API, version: 1.0 }
                paths:
                  /users:
                    get:
                      responses:
                        '200':
                          description: User found
                          content:
                            application/json:
                              schema:
                                $ref: '#/components/schemas/UserDto'
                components:
                  schemas:
                    UserDto:
                      type: object
                      required: [id, name]
                      properties:
                        id: { type: integer }
                        name: { type: string }
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        ApiEndpoint endpoint = parsed.getEndpoints().get(0);
        ApiResponseSchema resp = endpoint.getResponses().get("200");
        ApiSchema userSchema = resp.getJsonSchema();

        assertNotNull(userSchema);
        assertEquals(SchemaType.OBJECT, userSchema.getType());
        assertEquals("#/components/schemas/UserDto", userSchema.getRef());
        assertTrue(userSchema.isRequired("id"));
        assertTrue(userSchema.isRequired("name"));
    }

    @Test
    @DisplayName("15. Circular reference detection and handling without infinite recursion")
    void testCircularReferenceHandling() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Graph API, version: 1.0 }
                paths:
                  /nodes:
                    get:
                      responses:
                        '200':
                          description: Node graph
                          content:
                            application/json:
                              schema:
                                $ref: '#/components/schemas/TreeNode'
                components:
                  schemas:
                    TreeNode:
                      type: object
                      properties:
                        name: { type: string }
                        parent:
                          $ref: '#/components/schemas/TreeNode'
                """;

        ParsedApiSpecification parsed = assertDoesNotThrow(() -> parser.parse(yaml));
        ApiEndpoint endpoint = parsed.getEndpoints().get(0);
        ApiSchema rootNode = endpoint.getResponses().get("200").getJsonSchema();

        assertNotNull(rootNode);
        assertEquals(SchemaType.OBJECT, rootNode.getType());
        ApiSchema parentProp = rootNode.getProperty("parent");
        assertNotNull(parentProp);
        assertTrue(parentProp.isCircular(), "Parent reference back to TreeNode should be flagged as circular");
    }

    @Test
    @DisplayName("16. Multiple response schemas per status code")
    void testMultipleResponses() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Status API, version: 1.0 }
                paths:
                  /records/{id}:
                    get:
                      responses:
                        '200':
                          description: Success
                          content:
                            application/json:
                              schema: { type: object }
                        '400':
                          description: Bad request
                        '404':
                          description: Record not found
                        '500':
                          description: Internal error
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        ApiEndpoint ep = parsed.getEndpoints().get(0);
        assertEquals(4, ep.getResponses().size());
        assertTrue(ep.getResponses().get("200").isSuccess());
        assertTrue(ep.getResponses().get("400").isClientError());
        assertTrue(ep.getResponses().get("404").isClientError());
        assertTrue(ep.getResponses().get("500").isServerError());
    }

    @Test
    @DisplayName("17. Authentication and security requirements extraction")
    void testSecurityRequirements() {
        String yaml = """
                openapi: 3.0.0
                info: { title: Secured API, version: 1.0 }
                paths:
                  /admin/data:
                    get:
                      security:
                        - BearerAuth: []
                        - ApiKeyHeader: []
                      responses:
                        '200': { description: OK }
                components:
                  securitySchemes:
                    BearerAuth:
                      type: http
                      scheme: bearer
                      bearerFormat: JWT
                    ApiKeyHeader:
                      type: apiKey
                      in: header
                      name: X-API-KEY
                """;

        ParsedApiSpecification parsed = parser.parse(yaml);
        ApiEndpoint ep = parsed.getEndpoints().get(0);
        List<ApiSecurityRequirement> secList = ep.getSecurityRequirements();
        assertEquals(2, secList.size());

        ApiSecurityRequirement bearer = secList.stream()
                .filter(ApiSecurityRequirement::isBearerAuth)
                .findFirst().orElseThrow();
        assertEquals("bearer", bearer.getScheme());
        assertEquals("JWT", bearer.getBearerFormat());

        ApiSecurityRequirement apiKey = secList.stream()
                .filter(ApiSecurityRequirement::isApiKey)
                .findFirst().orElseThrow();
        assertEquals("header", apiKey.getIn());
        assertEquals("X-API-KEY", apiKey.getParamName());
    }

    @Test
    @DisplayName("18. Malformed specification handling with meaningful exception")
    void testMalformedSpecification() {
        String malformed = "{ this is completely broken json ... ::::";
        OpenApiParseException ex = assertThrows(OpenApiParseException.class, () -> parser.parse(malformed));
        assertNotNull(ex.getMessage());

        assertThrows(OpenApiParseException.class, () -> parser.parse(""));
        assertThrows(OpenApiParseException.class, () -> parser.parse((String) null));
    }

    @Test
    @DisplayName("19. Swagger 2.0 backward compatibility")
    void testSwagger2Compatibility() {
        String swagger2Json = """
                {
                  "swagger": "2.0",
                  "info": {
                    "title": "Swagger Petstore",
                    "version": "1.0.0"
                  },
                  "paths": {
                    "/pet/{petId}": {
                      "get": {
                        "summary": "Find pet by ID",
                        "parameters": [
                          {
                            "name": "petId",
                            "in": "path",
                            "required": true,
                            "type": "integer",
                            "format": "int64"
                          }
                        ],
                        "responses": {
                          "200": { "description": "successful operation" }
                        }
                      }
                    }
                  }
                }
                """;

        ParsedApiSpecification parsed = parser.parse(swagger2Json);
        assertNotNull(parsed);
        assertEquals("Swagger Petstore", parsed.getMetadata().getTitle());
        assertEquals(1, parsed.getEndpointsCount());

        ApiEndpoint endpoint = parsed.getEndpoints().get(0);
        assertEquals("/pet/{petId}", endpoint.getPath());
        assertEquals(HttpMethod.GET, endpoint.getMethod());
        ApiParameter param = endpoint.getPathParameters().get(0);
        assertEquals("petId", param.getName());
        assertEquals(SchemaType.INTEGER, param.getSchema().getType());
    }

    @Test
    @DisplayName("20. Large and deeply nested schema handling without stack overflow")
    void testDeeplyNestedSchema() {
        StringBuilder nested = new StringBuilder();
        int levels = 25;
        for (int i = 0; i < levels; i++) {
            nested.append("  ".repeat(i + 1)).append("level").append(i).append(":\n");
            nested.append("  ".repeat(i + 1)).append("  type: object\n");
            nested.append("  ".repeat(i + 1)).append("  properties:\n");
        }
        nested.append("  ".repeat(levels + 1)).append("leaf: { type: string }\n");

        String yaml = "openapi: 3.0.0\ninfo: { title: Deep API, version: 1.0 }\npaths:\n  /deep:\n    get:\n      responses:\n        '200':\n          content:\n            application/json:\n              schema:\n                type: object\n                properties:\n" + nested;

        ParsedApiSpecification parsed = assertDoesNotThrow(() -> parser.parse(yaml));
        assertNotNull(parsed);
        assertEquals(1, parsed.getEndpointsCount());
    }

    @Test
    @DisplayName("Parse from local file")
    void testParseFromFile() throws IOException {
        String yaml = """
                openapi: 3.0.0
                info: { title: File Loaded API, version: 1.0 }
                paths:
                  /ping:
                    get: { responses: { '200': { description: OK } } }
                """;
        File temp = File.createTempFile("openapi-file-", ".yaml");
        temp.deleteOnExit();
        Files.writeString(temp.toPath(), yaml);

        ParsedApiSpecification parsed = parser.parse(temp);
        assertEquals("File Loaded API", parsed.getMetadata().getTitle());
        assertEquals(1, parsed.getEndpointsCount());
    }
}
