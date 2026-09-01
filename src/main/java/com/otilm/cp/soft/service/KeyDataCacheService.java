package com.otilm.cp.soft.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.cp.soft.model.CachedKeyData;

import java.util.UUID;

public interface KeyDataCacheService {

    /**
     * Returns the cached {@link CachedKeyData} DTO for the given key UUID, loading it from the {@code key_data} table
     * on a cache miss and serving it from the Caffeine "keydata" cache on a hit.
     *
     * <p>
     * The cache key is {@code keyUuid}.
     * </p>
     *
     * @throws NotFoundException if no row exists for the given UUID.
     */
    CachedKeyData getCachedKeyData(UUID keyUuid) throws NotFoundException;

    /**
     * Schedules eviction of the cached DTO for the given key UUID so that it fires <em>after</em> the surrounding
     * database transaction commits. If called outside an active transaction, the eviction is applied immediately.
     */
    void evictAfterCommit(UUID keyUuid);
}
