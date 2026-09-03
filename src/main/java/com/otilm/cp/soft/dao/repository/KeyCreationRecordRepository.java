package com.otilm.cp.soft.dao.repository;

import com.otilm.cp.soft.dao.entity.KeyCreationRecord;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface KeyCreationRecordRepository extends JpaRepository<KeyCreationRecord, UUID> {

    Optional<KeyCreationRecord> findByCreationId(String creationId);
}
