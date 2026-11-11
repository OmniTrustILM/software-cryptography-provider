package com.otilm.cp.soft.dao.repository;

import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.model.TokenVersion;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenInstanceRepository extends JpaRepository<TokenInstance, Long> {

    String TOKEN_VERSION = "select new com.otilm.cp.soft.model.TokenVersion(t.uuid, t.name, t.timestamp,"
            + " case when t.code is not null then true else false end) from TokenInstance t";

    @Lock(LockModeType.OPTIMISTIC)
    Optional<TokenInstance> findByName(String name);

    @Lock(LockModeType.OPTIMISTIC)
    Optional<TokenInstance> findByUuid(UUID uuid);

    @Query(TOKEN_VERSION + " where t.name = :name")
    Optional<TokenVersion> findVersionByName(String name);

    @Query(TOKEN_VERSION + " where t.uuid = :uuid")
    Optional<TokenVersion> findVersionByUuid(UUID uuid);
}
