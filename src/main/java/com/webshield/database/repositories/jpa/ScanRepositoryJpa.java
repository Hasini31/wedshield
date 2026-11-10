package com.webshield.database.repositories.jpa;

import com.webshield.database.entities.ScanEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for {@link ScanEntity}.
 */
@Repository
public interface ScanRepositoryJpa extends JpaRepository<ScanEntity, Long> {

    List<ScanEntity> findByUserIdOrderByCreatedAtDesc(Long userId);

    Optional<ScanEntity> findByIdAndUserId(Long id, Long userId);

    long countByUserId(Long userId);
}

