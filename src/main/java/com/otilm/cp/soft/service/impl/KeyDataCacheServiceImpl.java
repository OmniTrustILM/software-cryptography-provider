package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.cp.soft.config.CacheConfig;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.dao.repository.KeyDataRepository;
import com.otilm.cp.soft.model.CachedKeyData;
import com.otilm.cp.soft.model.CachedKeyMaterial;
import com.otilm.cp.soft.service.KeyDataCacheService;
import java.sql.Timestamp;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
public class KeyDataCacheServiceImpl implements KeyDataCacheService {

    private static final Logger logger = LoggerFactory.getLogger(KeyDataCacheServiceImpl.class);

    private final CacheManager cacheManager;
    private final KeyDataRepository keyDataRepository;

    public KeyDataCacheServiceImpl(CacheManager cacheManager, KeyDataRepository keyDataRepository) {
        this.cacheManager = cacheManager;
        this.keyDataRepository = keyDataRepository;
    }

    @Override
    public CachedKeyData getCachedKeyData(UUID keyUuid, CachedKeyMaterial material) throws NotFoundException {
        RowWithMaterialVersion cached = keydata().get(keyUuid, RowWithMaterialVersion.class);
        if (cached != null && cached.materialVersion().equals(material.builtFrom())) {
            return cached.row();
        }
        CachedKeyData row = rowFromDatabase(keyUuid);
        keydata().put(keyUuid, new RowWithMaterialVersion(row, material.builtFrom()));
        return row;
    }

    private Cache keydata() {
        return Objects.requireNonNull(cacheManager.getCache(CacheConfig.KEYDATA_CACHE));
    }

    private CachedKeyData rowFromDatabase(UUID keyUuid) throws NotFoundException {
        logger.debug("Cache miss — loading KeyData {} from database", keyUuid);

        KeyData entity = keyDataRepository
                .findByUuid(keyUuid)
                .orElseThrow(() -> new NotFoundException(KeyData.class, keyUuid));

        var md = entity.getMetadata();
        return new CachedKeyData(entity.getUuid(), entity.getTokenInstanceUuid(), entity.getName(),
                entity.getAssociation(), entity.getType(), entity.getAlgorithm(), entity.getFormat(), entity.getValue(),
                entity.getLength(), md != null ? Collections.unmodifiableList(md) : List.of());
    }

    @Override
    public void evictAfterCommit(UUID keyUuid) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    doEvict(keyUuid);
                }
            });
        } else {
            logger.debug("evictAfterCommit called outside a transaction for key {}; evicting immediately", keyUuid);
            doEvict(keyUuid);
        }
    }

    private void doEvict(UUID keyUuid) {
        Cache cache = cacheManager.getCache(CacheConfig.KEYDATA_CACHE);
        if (cache != null) {
            cache.evict(keyUuid);
            logger.debug("Evicted cached KeyData {}", keyUuid);
        }
    }

    private record RowWithMaterialVersion(CachedKeyData row, Timestamp materialVersion) {
    }
}
