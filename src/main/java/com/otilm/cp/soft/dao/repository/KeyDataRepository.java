package com.otilm.cp.soft.dao.repository;

import com.otilm.cp.soft.dao.entity.KeyData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface KeyDataRepository extends JpaRepository<KeyData, Long> {

    List<KeyData> findByNameAndTokenInstanceUuid(String name, UUID tokenInstanceUuid);

    Optional<KeyData> findByUuid(UUID uuid);

    List<KeyData> findAllByTokenInstanceUuid(UUID uuid);

}