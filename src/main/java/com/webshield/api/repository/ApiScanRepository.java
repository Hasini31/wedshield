package com.webshield.api.repository;

import com.webshield.database.entities.ApiScanEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for {@link ApiScanEntity}.
 * All operations enforce user ownership boundaries.
 */
@Repository
public interface ApiScanRepository extends JpaRepository<ApiScanEntity, Long> {

    List<ApiScanEntity> findByUserIdOrderByCreatedAtDesc(Long userId);

    Page<ApiScanEntity> findByUserIdOrderByCreatedAtDesc(Long userId, Pageable pageable);

    Optional<ApiScanEntity> findByIdAndUserId(Long id, Long userId);

    List<ApiScanEntity> findByApiProjectIdAndUserIdOrderByCreatedAtDesc(Long apiProjectId, Long userId);

    Page<ApiScanEntity> findByApiProjectIdAndUserIdOrderByCreatedAtDesc(Long apiProjectId, Long userId, Pageable pageable);

    long countByUserId(Long userId);

    long countByApiProjectIdAndUserId(Long apiProjectId, Long userId);
}

