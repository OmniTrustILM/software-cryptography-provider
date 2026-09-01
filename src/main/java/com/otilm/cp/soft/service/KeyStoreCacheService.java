package com.otilm.cp.soft.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.cp.soft.model.CachedKeyMaterial;

import java.util.UUID;

public interface KeyStoreCacheService {

    /**
     * Returns the extracted key material for the token with the given UUID, loading it from the database on a cache
     * miss and serving it from the Caffeine "keystores" cache on a hit.
     *
     * <p>
     * On a cache miss the service resolves the {@code TokenInstance} internally via {@code TokenInstanceRepository}.
     * </p>
     *
     * @throws NotFoundException if no token instance exists for the given UUID.
     */
    CachedKeyMaterial loadKeyMaterial(UUID tokenInstanceUuid) throws NotFoundException;

    /**
     * Schedules eviction of the cached key material for the given token instance UUID so that it fires <em>after</em>
     * the surrounding database transaction commits. If called outside an active transaction, the eviction is applied
     * immediately.
     */
    void evictAfterCommit(UUID tokenInstanceUuid);
}
