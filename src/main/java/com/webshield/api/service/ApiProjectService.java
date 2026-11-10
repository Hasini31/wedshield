package com.webshield.api.service;

import com.webshield.api.models.ApiProject;
import com.webshield.api.models.SourceType;
import com.webshield.api.models.SpecFormat;
import com.webshield.api.models.SpecType;
import com.webshield.api.repository.ApiProjectRepository;
import com.webshield.auth.SessionManager;
import com.webshield.config.SpringContext;
import com.webshield.database.entities.ApiProjectEntity;
import com.webshield.models.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.util.List;
import java.util.Optional;

/**
 * Service managing API Security Testing projects and specification lifecycles.
 * Enforces per-user data isolation and strict input validation.
 */
@Service
public class ApiProjectService {

    private static final Logger log = LoggerFactory.getLogger(ApiProjectService.class);

    private final ApiProjectRepository repository;
    private final ApiSpecificationImporter importer;

    public ApiProjectService() {
        this(SpringContext.getBean(ApiProjectRepository.class),
             SpringContext.getBean(ApiSpecificationImporter.class) != null
                     ? SpringContext.getBean(ApiSpecificationImporter.class)
                     : new ApiSpecificationImporter());
    }

    @Autowired
    public ApiProjectService(ApiProjectRepository repository, ApiSpecificationImporter importer) {
        this.repository = repository;
        this.importer = importer != null ? importer : new ApiSpecificationImporter();
    }

    private long getAuthenticatedUserId() {
        User user = SessionManager.getInstance().getCurrentUser();
        if (user == null) {
            throw new IllegalStateException("User must be authenticated to perform API project operations.");
        }
        return (long) user.getId();
    }

    /**
     * Creates a new API project from raw specification content.
     */
    @Transactional
    public ApiProject createProject(String name, String description, SourceType sourceType,
                                    String sourceUrl, String rawSpec) {
        long userId = getAuthenticatedUserId();

        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Project name cannot be empty.");
        }
        String trimmedName = name.trim();
        if (trimmedName.length() > 150) {
            throw new IllegalArgumentException("Project name exceeds maximum length of 150 characters.");
        }

        if (repository != null && repository.existsByUserIdAndName(userId, trimmedName)) {
            throw new IllegalArgumentException("An API project with the name '" + trimmedName + "' already exists under your account.");
        }

        SpecInspectionResult inspection = importer.validateAndInspect(rawSpec);

        ApiProjectEntity entity = new ApiProjectEntity(
                userId,
                trimmedName,
                description != null ? description.trim() : null,
                inspection.specType(),
                inspection.specFormat(),
                sourceType != null ? sourceType : SourceType.FILE_UPLOAD,
                sourceUrl != null ? sourceUrl.trim() : null,
                rawSpec,
                inspection.endpointsCount()
        );

        if (repository != null) {
            entity = repository.save(entity);
            log.info("Created API project id={} name='{}' for user id={}", entity.getId(), entity.getName(), userId);
        }

        return toModel(entity);
    }

    /**
     * Imports an API project from a local file.
     */
    public ApiProject importFromFile(String name, String description, File file) {
        String content = importer.readFromFile(file);
        String effectiveName = (name != null && !name.isBlank()) ? name : file.getName();
        return createProject(effectiveName, description, SourceType.FILE_UPLOAD, file.getName(), content);
    }

    /**
     * Imports an API project from a remote specification URL.
     */
    public ApiProject importFromUrl(String name, String description, String url) {
        String content = importer.fetchFromUrl(url);
        String effectiveName = name;
        if (effectiveName == null || effectiveName.isBlank()) {
            try {
                SpecInspectionResult insp = importer.validateAndInspect(content);
                if (insp.title() != null && !insp.title().equals("Untitled API")) {
                    effectiveName = insp.title();
                }
            } catch (Exception ignored) {
            }
            if (effectiveName == null || effectiveName.isBlank()) {
                effectiveName = "Imported API Project";
            }
        }
        return createProject(effectiveName, description, SourceType.URL, url, content);
    }

    /**
     * Retrieves all API projects owned by the currently authenticated user.
     */
    public List<ApiProject> getProjectsForCurrentUser() {
        long userId = getAuthenticatedUserId();
        if (repository == null) {
            return List.of();
        }
        return repository.findByUserIdOrderByCreatedAtDesc(userId)
                .stream()
                .map(this::toModel)
                .toList();
    }

    /**
     * Retrieves a single project by ID, ensuring user ownership.
     */
    public Optional<ApiProject> getProject(Long id) {
        if (id == null) {
            return Optional.empty();
        }
        long userId = getAuthenticatedUserId();
        if (repository == null) {
            return Optional.empty();
        }
        return repository.findByIdAndUserId(id, userId).map(this::toModel);
    }

    /**
     * Updates an existing API project's metadata.
     */
    @Transactional
    public ApiProject updateProject(Long id, String name, String description) {
        if (id == null) {
            throw new IllegalArgumentException("Project ID cannot be null.");
        }
        long userId = getAuthenticatedUserId();

        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Project name cannot be empty.");
        }
        String trimmedName = name.trim();
        if (trimmedName.length() > 150) {
            throw new IllegalArgumentException("Project name exceeds maximum length of 150 characters.");
        }

        if (repository == null) {
            throw new IllegalStateException("Repository unavailable");
        }

        ApiProjectEntity entity = repository.findByIdAndUserId(id, userId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found with id: " + id));

        if (repository.existsByUserIdAndNameAndIdNot(userId, trimmedName, id)) {
            throw new IllegalArgumentException("Another API project with the name '" + trimmedName + "' already exists.");
        }

        entity.setName(trimmedName);
        entity.setDescription(description != null ? description.trim() : null);

        ApiProjectEntity updated = repository.save(entity);
        log.info("Updated API project id={} name='{}' for user id={}", updated.getId(), updated.getName(), userId);
        return toModel(updated);
    }

    /**
     * Deletes an API project by ID, ensuring user ownership.
     */
    @Transactional
    public boolean deleteProject(Long id) {
        if (id == null) {
            return false;
        }
        long userId = getAuthenticatedUserId();
        if (repository == null) {
            return false;
        }

        Optional<ApiProjectEntity> opt = repository.findByIdAndUserId(id, userId);
        if (opt.isPresent()) {
            repository.delete(opt.get());
            log.info("Deleted API project id={} for user id={}", id, userId);
            return true;
        }
        return false;
    }

    /**
     * Returns total project count for the current user.
     */
    public long countProjectsForCurrentUser() {
        long userId = getAuthenticatedUserId();
        return repository != null ? repository.countByUserId(userId) : 0;
    }

    private ApiProject toModel(ApiProjectEntity entity) {
        if (entity == null) {
            return null;
        }
        return new ApiProject(
                entity.getId(),
                entity.getUserId(),
                entity.getName(),
                entity.getDescription(),
                entity.getSpecType() != null ? entity.getSpecType() : SpecType.OPENAPI_3,
                entity.getSpecFormat() != null ? entity.getSpecFormat() : SpecFormat.JSON,
                entity.getSourceType() != null ? entity.getSourceType() : SourceType.FILE_UPLOAD,
                entity.getSourceUrl(),
                entity.getRawSpecification(),
                entity.getEndpointsCount(),
                entity.getCreatedAt(),
                entity.getUpdatedAt()
        );
    }
}

