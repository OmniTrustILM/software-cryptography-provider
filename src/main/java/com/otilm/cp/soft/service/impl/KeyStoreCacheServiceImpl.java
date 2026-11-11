package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.dao.repository.TokenInstanceRepository;
import com.otilm.cp.soft.model.CachedKeyMaterial;
import com.otilm.cp.soft.model.TokenVersion;
import com.otilm.cp.soft.service.KeyStoreCacheService;
import java.sql.Timestamp;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
public class KeyStoreCacheServiceImpl implements KeyStoreCacheService {
    private static final Logger logger = LoggerFactory.getLogger(KeyStoreCacheServiceImpl.class);

    private final KeyMaterialCache keyMaterialCache;
    private final TokenInstanceRepository tokenInstanceRepository;

    public KeyStoreCacheServiceImpl(KeyMaterialCache keyMaterialCache,
            TokenInstanceRepository tokenInstanceRepository) {
        this.keyMaterialCache = keyMaterialCache;
        this.tokenInstanceRepository = tokenInstanceRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public CachedKeyMaterial loadKeyMaterial(UUID tokenInstanceUuid) throws NotFoundException {
        return keyMaterialFor(tokenInstanceRepository
                .findVersionByUuid(tokenInstanceUuid)
                .orElseThrow(() -> new NotFoundException(TokenInstance.class, tokenInstanceUuid)));
    }

    @Override
    @Transactional(readOnly = true)
    public CachedKeyMaterial loadKeyMaterial(TokenVersion observed) throws NotFoundException {
        return keyMaterialFor(observed);
    }

    private CachedKeyMaterial keyMaterialFor(TokenVersion observed) throws NotFoundException {
        UUID tokenInstanceUuid = observed.uuid();
        CachedKeyMaterial kept = keyMaterialCache.kept(tokenInstanceUuid);
        if (kept != null && isStillWhatTheTokenHolds(kept, observed.timestamp())) {
            return kept;
        }

        TokenInstance tokenInstance = tokenInstanceRepository
                .findByUuid(tokenInstanceUuid)
                .orElseThrow(() -> new NotFoundException(TokenInstance.class, tokenInstanceUuid));
        CachedKeyMaterial material = keyMaterialCache.of(tokenInstanceUuid, tokenInstance);
        if (isStillWhatTheTokenHolds(material, tokenInstance.getTimestamp())) {
            return material;
        }

        logger
                .debug("Cached key material for token instance {} was extracted from another version; loading"
                        + " it again", tokenInstanceUuid);
        keyMaterialCache.evictIfStillCached(tokenInstanceUuid, material);
        return keyMaterialCache.of(tokenInstanceUuid, tokenInstance);
    }

    /**
     * Whether the material was extracted from the token as it now stands.
     *
     * <p>
     * Every change to a token's keys advances the version of its row, so material extracted from an older version is
     * material the token no longer holds. All connector instances read the version from the database on every request.
     * </p>
     */
    private static boolean isStillWhatTheTokenHolds(CachedKeyMaterial material, Timestamp version) {
        return Objects.equals(material.builtFrom(), version);
    }

    /**
     * Schedules cache eviction to run after the current transaction commits.
     *
     * <p>
     * <b>Consistency guarantee (eventual, not strict):</b> eviction fires in the {@code afterCommit} phase of Spring's
     * transaction synchronization, which runs <em>after</em> the database row has already been made visible to other
     * transactions.
     * </p>
     *
     * <p>
     * In the narrow window between commit and the synchronization callback, a concurrent reader <em>could</em>
     * repopulate the cache with the newly-written value — which is correct — rather than the stale value. This is
     * benign (the cached value is never stale-after-eviction, only potentially refreshed a few microseconds early), but
     * callers should not assume strict linearizability between writes and cache state.
     * </p>
     */
    @Override
    public void evictAfterCommit(UUID tokenInstanceUuid) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    doEvict(tokenInstanceUuid);
                }
            });
        } else {
            logger
                    .debug("evictAfterCommit called outside a transaction for token instance {}; evicting immediately",
                            tokenInstanceUuid);
            doEvict(tokenInstanceUuid);
        }
    }

    private void doEvict(UUID tokenInstanceUuid) {
        keyMaterialCache.forget(tokenInstanceUuid);
    }
}
