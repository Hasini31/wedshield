package com.webshield.api.repository;

import com.webshield.database.entities.ApiReportEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for persisting and querying API security report metadata.
 */
@Repository
public interface ApiReportRepository extends JpaRepository<ApiReportEntity, Long> {

    List<ApiReportEntity> findByUserIdOrderByCreatedAtDesc(Long userId);

    List<ApiReportEntity> findByApiScanIdAndUserIdOrderByCreatedAtDesc(Long apiScanId, Long userId);

    Optional<ApiReportEntity> findByIdAndUserId(Long id, Long userId);

    void deleteByIdAndUserId(Long id, Long userId);
}

