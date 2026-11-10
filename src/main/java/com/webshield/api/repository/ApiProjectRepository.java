package com.webshield.api.repository;

import com.webshield.database.entities.ApiProjectEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for {@link ApiProjectEntity}.
 * All operations are strictly scoped by the authenticated user's ID.
 */
@Repository
public interface ApiProjectRepository extends JpaRepository<ApiProjectEntity, Long> {

    List<ApiProjectEntity> findByUserIdOrderByCreatedAtDesc(Long userId);

    Optional<ApiProjectEntity> findByIdAndUserId(Long id, Long userId);

    boolean existsByUserIdAndName(Long userId, String name);

    boolean existsByUserIdAndNameAndIdNot(Long userId, String name, Long id);

    long countByUserId(Long userId);
}

