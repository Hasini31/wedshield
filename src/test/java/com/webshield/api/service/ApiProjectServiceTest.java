package com.webshield.api.service;

import com.webshield.api.models.ApiProject;
import com.webshield.api.models.SourceType;
import com.webshield.api.models.SpecFormat;
import com.webshield.api.models.SpecType;
import com.webshield.api.repository.ApiProjectRepository;
import com.webshield.auth.SessionManager;
import com.webshield.database.entities.ApiProjectEntity;
import com.webshield.models.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.repository.query.FluentQuery;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Module A: ApiProjectService & Specification Importer Tests")
class ApiProjectServiceTest {

    private InMemoryApiProjectRepository repository;
    private ApiSpecificationImporter importer;
    private ApiProjectService service;

    private static final String VALID_OPENAPI_3_JSON = """
            {
              "openapi": "3.0.3",
              "info": {
                "title": "Petstore Inventory API",
                "version": "1.0.0"
              },
              "paths": {
                "/pets": {
                  "get": { "summary": "List pets" },
                  "post": { "summary": "Create pet" }
                },
                "/pets/{id}": {
                  "get": { "summary": "Get pet by ID" },
                  "delete": { "summary": "Delete pet" }
                }
              }
            }
            """;

    private static final String VALID_OPENAPI_3_YAML = """
            openapi: 3.0.0
            info:
              title: Customers Microservice
              version: 2.1.0
            paths:
              /customers:
                get:
                  summary: List customers
              /customers/{id}:
                get:
                  summary: Get customer
                put:
                  summary: Update customer
            """;

    private static final String VALID_SWAGGER_2_JSON = """
            {
              "swagger": "2.0",
              "info": {
                "title": "Legacy Swagger API",
                "version": "2.0"
              },
              "paths": {
                "/health": {
                  "get": { "summary": "Service health status" }
                }
              }
            }
            """;

    @BeforeEach
    void setUp() {
        repository = new InMemoryApiProjectRepository();
        importer = new ApiSpecificationImporter();
        service = new ApiProjectService(repository, importer);

        // Login default test user (ID 1)
        User testUser = new User(1, "Alice Security", "alice@webshield.io", "hash", LocalDateTime.now(), LocalDateTime.now());
        SessionManager.getInstance().login(testUser);
    }

    @AfterEach
    void tearDown() {
        SessionManager.getInstance().logout();
    }

    @Test
    @DisplayName("Create project successfully from valid OpenAPI 3.0 JSON specification")
    void testCreateProjectFromOpenApiJson() {
        ApiProject project = service.createProject("Petstore", "Testing petstore endpoints",
                SourceType.FILE_UPLOAD, "petstore.json", VALID_OPENAPI_3_JSON);

        assertNotNull(project);
        assertEquals(1L, project.getId());
        assertEquals(1L, project.getUserId());
        assertEquals("Petstore", project.getName());
        assertEquals("Testing petstore endpoints", project.getDescription());
        assertEquals(SpecType.OPENAPI_3, project.getSpecType());
        assertEquals(SpecFormat.JSON, project.getSpecFormat());
        assertEquals(4, project.getEndpointsCount());
        assertEquals(SourceType.FILE_UPLOAD, project.getSourceType());
        assertEquals("petstore.json", project.getSourceUrl());
    }

    @Test
    @DisplayName("Create project successfully from valid OpenAPI 3.0 YAML specification")
    void testCreateProjectFromOpenApiYaml() {
        ApiProject project = service.createProject("Customers API", "Customer microservice",
                SourceType.FILE_UPLOAD, "customers.yaml", VALID_OPENAPI_3_YAML);

        assertNotNull(project);
        assertEquals(SpecType.OPENAPI_3, project.getSpecType());
        assertEquals(SpecFormat.YAML, project.getSpecFormat());
        assertEquals(3, project.getEndpointsCount());
    }

    @Test
    @DisplayName("Create project successfully from valid Swagger 2.0 specification")
    void testCreateProjectFromSwagger2() {
        ApiProject project = service.createProject("Legacy System", "Legacy swagger check",
                SourceType.FILE_UPLOAD, "swagger.json", VALID_SWAGGER_2_JSON);

        assertNotNull(project);
        assertEquals(SpecType.SWAGGER_2, project.getSpecType());
        assertEquals(SpecFormat.JSON, project.getSpecFormat());
        assertEquals(1, project.getEndpointsCount());
    }

    @Test
    @DisplayName("Reject specification missing required openapi or swagger root fields")
    void testRejectMissingOpenApiOrSwaggerField() {
        String invalidSpec = """
                {
                  "info": { "title": "Incomplete API" },
                  "paths": {}
                }
                """;

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                service.createProject("Invalid Spec", "Missing openapi version",
                        SourceType.FILE_UPLOAD, null, invalidSpec));

        assertTrue(ex.getMessage().contains("missing required 'openapi' or 'swagger'"));
    }

    @Test
    @DisplayName("Reject malformed JSON or YAML syntax")
    void testRejectMalformedSyntax() {
        String brokenJson = "{\"openapi\": \"3.0.0\", \"paths\": { broken json syntax ...";

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                service.createProject("Broken Spec", null, SourceType.FILE_UPLOAD, null, brokenJson));

        assertTrue(ex.getMessage().toLowerCase().contains("malformed")
                || ex.getMessage().toLowerCase().contains("syntax")
                || ex.getMessage().toLowerCase().contains("yaml"));
    }

    @Test
    @DisplayName("Reject specification exceeding 5 MB size limit")
    void testRejectOversizedSpecification() {
        int targetSize = (int) ApiSpecificationImporter.MAX_SPEC_SIZE_BYTES + 1024;
        String largePadding = "a".repeat(targetSize);
        String oversizedSpec = "{\"openapi\": \"3.0.0\", \"info\": {\"title\": \"" + largePadding + "\"}, \"paths\": {}}";

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                service.createProject("Huge Spec", null, SourceType.FILE_UPLOAD, null, oversizedSpec));

        assertTrue(ex.getMessage().contains("exceeds maximum permitted limit of 5242880 bytes")
                || ex.getMessage().contains("5 MB"));
    }

    @Test
    @DisplayName("Reject empty or blank specification content")
    void testRejectBlankSpecification() {
        assertThrows(IllegalArgumentException.class, () ->
                service.createProject("Blank Spec", null, SourceType.FILE_UPLOAD, null, "   "));
        assertThrows(IllegalArgumentException.class, () ->
                service.createProject("Null Spec", null, SourceType.FILE_UPLOAD, null, null));
    }

    @Test
    @DisplayName("Reject blank or invalid project name")
    void testRejectInvalidProjectName() {
        assertThrows(IllegalArgumentException.class, () ->
                service.createProject("   ", null, SourceType.FILE_UPLOAD, null, VALID_OPENAPI_3_JSON));
        assertThrows(IllegalArgumentException.class, () ->
                service.createProject("a".repeat(151), null, SourceType.FILE_UPLOAD, null, VALID_OPENAPI_3_JSON));
    }

    @Test
    @DisplayName("Reject duplicate project name for the same user")
    void testRejectDuplicateProjectName() {
        service.createProject("Billing API", "First instance", SourceType.FILE_UPLOAD, null, VALID_OPENAPI_3_JSON);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                service.createProject("Billing API", "Duplicate instance", SourceType.FILE_UPLOAD, null, VALID_OPENAPI_3_JSON));

        assertTrue(ex.getMessage().contains("already exists under your account"));
    }

    @Test
    @DisplayName("Reject unauthenticated user operations with IllegalStateException")
    void testRejectUnauthenticatedUser() {
        SessionManager.getInstance().logout();

        assertThrows(IllegalStateException.class, () ->
                service.createProject("Test", null, SourceType.FILE_UPLOAD, null, VALID_OPENAPI_3_JSON));
        assertThrows(IllegalStateException.class, () -> service.getProjectsForCurrentUser());
        assertThrows(IllegalStateException.class, () -> service.getProject(1L));
        assertThrows(IllegalStateException.class, () -> service.updateProject(1L, "New Name", null));
        assertThrows(IllegalStateException.class, () -> service.deleteProject(1L));
    }

    @Test
    @DisplayName("User data isolation: projects belonging to other users are not accessible")
    void testUserDataIsolation() {
        // Alice (user 1) creates a project
        ApiProject aliceProject = service.createProject("Alice Project", "Confidential",
                SourceType.FILE_UPLOAD, null, VALID_OPENAPI_3_JSON);

        // Switch session to Bob (user 2)
        User bob = new User(2, "Bob Auditor", "bob@webshield.io", "hash", LocalDateTime.now(), LocalDateTime.now());
        SessionManager.getInstance().login(bob);

        // Bob should see 0 projects
        List<ApiProject> bobProjects = service.getProjectsForCurrentUser();
        assertTrue(bobProjects.isEmpty());

        // Bob cannot fetch Alice's project by ID
        Optional<ApiProject> fetched = service.getProject(aliceProject.getId());
        assertTrue(fetched.isEmpty());

        // Bob cannot delete Alice's project
        boolean deleted = service.deleteProject(aliceProject.getId());
        assertFalse(deleted);

        // Bob can create a project with the same name without collision
        ApiProject bobProject = service.createProject("Alice Project", "Bob's separate version",
                SourceType.FILE_UPLOAD, null, VALID_OPENAPI_3_JSON);
        assertNotNull(bobProject);
        assertEquals(2L, bobProject.getUserId());
    }

    @Test
    @DisplayName("Update project name and description successfully")
    void testUpdateProject() {
        ApiProject created = service.createProject("Original Name", "Old description",
                SourceType.FILE_UPLOAD, null, VALID_OPENAPI_3_JSON);

        ApiProject updated = service.updateProject(created.getId(), "Renamed Service", "New description");

        assertEquals("Renamed Service", updated.getName());
        assertEquals("New description", updated.getDescription());

        // Verify update rejected if duplicate name chosen
        service.createProject("Existing Other Project", null, SourceType.FILE_UPLOAD, null, VALID_OPENAPI_3_JSON);
        assertThrows(IllegalArgumentException.class, () ->
                service.updateProject(created.getId(), "Existing Other Project", null));
    }

    @Test
    @DisplayName("Delete project successfully removes it")
    void testDeleteProject() {
        ApiProject project = service.createProject("Temporary Project", null,
                SourceType.FILE_UPLOAD, null, VALID_OPENAPI_3_JSON);

        boolean deleted = service.deleteProject(project.getId());
        assertTrue(deleted);

        Optional<ApiProject> retrieved = service.getProject(project.getId());
        assertTrue(retrieved.isEmpty());

        // Second deletion returns false
        assertFalse(service.deleteProject(project.getId()));
    }

    @Test
    @DisplayName("Import from local file reads and registers specification")
    void testImportFromFile() throws IOException {
        File tempFile = File.createTempFile("openapi-test-", ".json");
        tempFile.deleteOnExit();
        Files.writeString(tempFile.toPath(), VALID_OPENAPI_3_JSON);

        ApiProject project = service.importFromFile("File Project", "Loaded from disk", tempFile);

        assertNotNull(project);
        assertEquals("File Project", project.getName());
        assertEquals(SpecType.OPENAPI_3, project.getSpecType());
        assertEquals(4, project.getEndpointsCount());
    }

    @Test
    @DisplayName("Specification Importer blocks SSRF and restricted IP addresses")
    void testSsrfProtection() {
        assertThrows(IllegalArgumentException.class, () -> importer.fetchFromUrl("http://localhost:8080/openapi.json"));
        assertThrows(IllegalArgumentException.class, () -> importer.fetchFromUrl("http://127.0.0.1/spec.yaml"));
        assertThrows(IllegalArgumentException.class, () -> importer.fetchFromUrl("http://169.254.169.254/latest/meta-data"));
        assertThrows(IllegalArgumentException.class, () -> importer.fetchFromUrl("http://0.0.0.0/spec.json"));
        assertThrows(IllegalArgumentException.class, () -> importer.fetchFromUrl("ftp://example.com/spec.json"));
        assertThrows(IllegalArgumentException.class, () -> importer.fetchFromUrl(""));
    }

    /**
     * In-memory mock repository implementing {@link ApiProjectRepository} for isolated unit tests.
     */
    private static class InMemoryApiProjectRepository implements ApiProjectRepository {
        private final Map<Long, ApiProjectEntity> store = new HashMap<>();
        private final AtomicLong idGen = new AtomicLong(1);

        @Override
        public List<ApiProjectEntity> findByUserIdOrderByCreatedAtDesc(Long userId) {
            return store.values().stream()
                    .filter(e -> Objects.equals(e.getUserId(), userId))
                    .sorted((a, b) -> b.getCreatedAt().compareTo(a.getCreatedAt()))
                    .toList();
        }

        @Override
        public Optional<ApiProjectEntity> findByIdAndUserId(Long id, Long userId) {
            ApiProjectEntity entity = store.get(id);
            if (entity != null && Objects.equals(entity.getUserId(), userId)) {
                return Optional.of(entity);
            }
            return Optional.empty();
        }

        @Override
        public boolean existsByUserIdAndName(Long userId, String name) {
            return store.values().stream()
                    .anyMatch(e -> Objects.equals(e.getUserId(), userId) && e.getName().equalsIgnoreCase(name));
        }

        @Override
        public boolean existsByUserIdAndNameAndIdNot(Long userId, String name, Long id) {
            return store.values().stream()
                    .anyMatch(e -> Objects.equals(e.getUserId(), userId)
                            && !Objects.equals(e.getId(), id)
                            && e.getName().equalsIgnoreCase(name));
        }

        @Override
        public long countByUserId(Long userId) {
            return store.values().stream()
                    .filter(e -> Objects.equals(e.getUserId(), userId))
                    .count();
        }

        @Override
        public <S extends ApiProjectEntity> S save(S entity) {
            if (entity.getId() == null) {
                entity.setId(idGen.getAndIncrement());
            }
            store.put(entity.getId(), entity);
            return entity;
        }

        @Override
        public Optional<ApiProjectEntity> findById(Long id) {
            return Optional.ofNullable(store.get(id));
        }

        @Override
        public boolean existsById(Long id) {
            return store.containsKey(id);
        }

        @Override
        public long count() {
            return store.size();
        }

        @Override
        public void deleteById(Long id) {
            store.remove(id);
        }

        @Override
        public void delete(ApiProjectEntity entity) {
            if (entity != null && entity.getId() != null) {
                store.remove(entity.getId());
            }
        }

        @Override public void deleteAllById(Iterable<? extends Long> ids) {}
        @Override public void deleteAll(Iterable<? extends ApiProjectEntity> entities) {}
        @Override public void deleteAll() { store.clear(); }
        @Override public List<ApiProjectEntity> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<ApiProjectEntity> findAllById(Iterable<Long> ids) { return List.of(); }
        @Override public <S extends ApiProjectEntity> List<S> saveAll(Iterable<S> entities) { return List.of(); }
        @Override public void flush() {}
        @Override public <S extends ApiProjectEntity> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends ApiProjectEntity> List<S> saveAllAndFlush(Iterable<S> entities) { return List.of(); }
        @Override public void deleteAllInBatch(Iterable<ApiProjectEntity> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> ids) {}
        @Override public void deleteAllInBatch() {}
        @Override public ApiProjectEntity getOne(Long id) { return store.get(id); }
        @Override public ApiProjectEntity getById(Long id) { return store.get(id); }
        @Override public ApiProjectEntity getReferenceById(Long id) { return store.get(id); }
        @Override public <S extends ApiProjectEntity> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends ApiProjectEntity> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends ApiProjectEntity> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends ApiProjectEntity> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends ApiProjectEntity> long count(Example<S> example) { return 0; }
        @Override public <S extends ApiProjectEntity> boolean exists(Example<S> example) { return false; }
        @Override public <S extends ApiProjectEntity, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<ApiProjectEntity> findAll(Sort sort) { return List.of(); }
        @Override public Page<ApiProjectEntity> findAll(Pageable pageable) { return Page.empty(); }
    }
}

