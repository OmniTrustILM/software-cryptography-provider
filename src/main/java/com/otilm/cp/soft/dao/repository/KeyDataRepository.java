package com.otilm.cp.soft.dao.repository;

import com.otilm.cp.soft.dao.entity.KeyData;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface KeyDataRepository extends JpaRepository<KeyData, Long> {

    List<KeyData> findByNameAndTokenInstanceUuid(String name, UUID tokenInstanceUuid);

    Optional<KeyData> findByUuid(UUID uuid);

    List<KeyData> findAllByTokenInstanceUuid(UUID uuid);

    /**
     * Both halves a creation produced, which is how a repeated creation is answered with the key it already made. The
     * identifier is the platform's own and is not scoped to a token, so neither is the lookup: the same identifier
     * arriving for another token is a different request wearing it, not a creation of its own.
     */
    List<KeyData> findByKeyCreationId(String keyCreationId);

    /** Both halves an import produced, which is how a repeated import is answered with the key it already made. */
    List<KeyData> findByKeyImportId(String keyImportId);

}
