package com.webshield.database.repositories.jpa;

import com.webshield.database.entities.WebsiteEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for {@link WebsiteEntity}.
 */
@Repository
public interface WebsiteRepositoryJpa extends JpaRepository<WebsiteEntity, Long> {

    List<WebsiteEntity> findByUserIdOrderByCreatedAtDesc(Long userId);

    Optional<WebsiteEntity> findByIdAndUserId(Long id, Long userId);

    long countByUserId(Long userId);
}

