package com.webshield.api.repository;

import com.webshield.database.entities.ApiFindingEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for {@link ApiFindingEntity}.
 */
@Repository
public interface ApiFindingRepository extends JpaRepository<ApiFindingEntity, Long> {

    List<ApiFindingEntity> findByScanIdOrderByDetectedAtAsc(Long scanId);

    Page<ApiFindingEntity> findByScanIdOrderByDetectedAtAsc(Long scanId, Pageable pageable);

    List<ApiFindingEntity> findByScanIdAndSeverity(Long scanId, String severity);

    Page<ApiFindingEntity> findByScanIdAndSeverity(Long scanId, String severity, Pageable pageable);

    List<ApiFindingEntity> findByScanIdAndRuleId(Long scanId, String ruleId);

    List<ApiFindingEntity> findByScanIdAndEndpointPathContaining(Long scanId, String endpointPath);

    Optional<ApiFindingEntity> findByFindingUuid(String findingUuid);

    boolean existsByScanIdAndFindingUuid(Long scanId, String findingUuid);

    long countByScanId(Long scanId);

    long countByScanIdAndSeverity(Long scanId, String severity);
}

