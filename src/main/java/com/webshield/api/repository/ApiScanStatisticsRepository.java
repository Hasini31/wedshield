package com.webshield.api.repository;

import com.webshield.database.entities.ApiScanStatisticsEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Spring Data JPA repository for {@link ApiScanStatisticsEntity}.
 */
@Repository
public interface ApiScanStatisticsRepository extends JpaRepository<ApiScanStatisticsEntity, Long> {

    Optional<ApiScanStatisticsEntity> findByScanId(Long scanId);

    void deleteByScanId(Long scanId);
}

