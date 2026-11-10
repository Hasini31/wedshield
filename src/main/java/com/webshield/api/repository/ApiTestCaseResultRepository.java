package com.webshield.api.repository;

import com.webshield.database.entities.ApiTestCaseResultEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for {@link ApiTestCaseResultEntity}.
 */
@Repository
public interface ApiTestCaseResultRepository extends JpaRepository<ApiTestCaseResultEntity, Long> {

    List<ApiTestCaseResultEntity> findByScanIdOrderByCreatedAtAsc(Long scanId);

    Page<ApiTestCaseResultEntity> findByScanIdOrderByCreatedAtAsc(Long scanId, Pageable pageable);

    Optional<ApiTestCaseResultEntity> findByScanIdAndTestCaseId(Long scanId, String testCaseId);

    long countByScanId(Long scanId);

    long countByScanIdAndCategory(Long scanId, String category);
}

