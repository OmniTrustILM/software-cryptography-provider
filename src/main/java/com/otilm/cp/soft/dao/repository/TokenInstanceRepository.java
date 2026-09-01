package com.otilm.cp.soft.dao.repository;

import com.otilm.cp.soft.dao.entity.TokenInstance;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenInstanceRepository extends JpaRepository<TokenInstance, Long> {

    @Lock(LockModeType.OPTIMISTIC)
    Optional<TokenInstance> findByName(String name);

    @Lock(LockModeType.OPTIMISTIC)
    Optional<TokenInstance> findByUuid(UUID uuid);

}
