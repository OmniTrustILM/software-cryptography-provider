package com.otilm.cp.soft.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.cp.soft.model.CachedKeyMaterial;
import com.otilm.cp.soft.model.TokenVersion;

import java.util.UUID;

public interface KeyStoreCacheService {

    /**
     * Returns the extracted key material for the token with the given UUID. The cached copy is served while it was
     * extracted from the token's current version; otherwise the token is loaded from the database and extracted again.
     *
     * @throws NotFoundException if no token instance exists for the given UUID.
     */
    CachedKeyMaterial loadKeyMaterial(UUID tokenInstanceUuid) throws NotFoundException;

    /**
     * Returns the extracted key material for the token, like {@link #loadKeyMaterial(UUID)}, but compares the cached
     * copy with the given version instead of reading the current one from the database.
     *
     * @throws NotFoundException if the token instance is gone when it has to be loaded.
     */
    CachedKeyMaterial loadKeyMaterial(TokenVersion observed) throws NotFoundException;

    /**
     * Schedules eviction of the cached key material for the given token instance UUID so that it fires <em>after</em>
     * the surrounding database transaction commits. If called outside an active transaction, the eviction is applied
     * immediately.
     */
    void evictAfterCommit(UUID tokenInstanceUuid);
}
