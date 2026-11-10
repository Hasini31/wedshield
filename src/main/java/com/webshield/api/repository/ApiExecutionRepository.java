package com.webshield.api.repository;

import com.webshield.database.entities.ApiExecutionEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for {@link ApiExecutionEntity}.
 */
@Repository
public interface ApiExecutionRepository extends JpaRepository<ApiExecutionEntity, Long> {

    List<ApiExecutionEntity> findByScanIdOrderByExecutedAtAsc(Long scanId);

    Page<ApiExecutionEntity> findByScanIdOrderByExecutedAtAsc(Long scanId, Pageable pageable);

    Optional<ApiExecutionEntity> findByExecutionUuid(String executionUuid);

    List<ApiExecutionEntity> findByScanIdAndEndpointContaining(Long scanId, String endpoint);

    long countByScanId(Long scanId);

    long countByScanIdAndStatusCodeBetween(Long scanId, int startCode, int endCode);
}

