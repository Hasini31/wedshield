package com.webshield.database.repositories.jpa;

import com.webshield.database.entities.ScanFindingEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Spring Data JPA repository for {@link ScanFindingEntity}.
 */
@Repository
public interface FindingRepositoryJpa extends JpaRepository<ScanFindingEntity, Long> {

    List<ScanFindingEntity> findByScanIdOrderByDetectedAtDesc(Long scanId);

    long countByScanId(Long scanId);
}

