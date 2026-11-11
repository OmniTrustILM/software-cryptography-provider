package com.otilm.cp.soft.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.cp.soft.model.CachedKeyData;
import com.otilm.cp.soft.model.CachedKeyMaterial;

import java.util.UUID;

public interface KeyDataCacheService {

    /**
     * Returns the key's row, reusing the cached copy only when it was read with the same version of the given key
     * material. In a newer version, the key's alias may already belong to another key.
     *
     * @throws NotFoundException if no row exists for the given UUID.
     */
    CachedKeyData getCachedKeyData(UUID keyUuid, CachedKeyMaterial material) throws NotFoundException;

    /**
     * Schedules eviction of the cached DTO for the given key UUID so that it fires <em>after</em> the surrounding
     * database transaction commits. If called outside an active transaction, the eviction is applied immediately.
     */
    void evictAfterCommit(UUID keyUuid);
}
