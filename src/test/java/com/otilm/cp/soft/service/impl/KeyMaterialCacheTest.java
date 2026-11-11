package com.otilm.cp.soft.service.impl;

import com.otilm.cp.soft.config.CacheConfig;
import com.otilm.cp.soft.model.CachedKeyMaterial;
import java.sql.Timestamp;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

class KeyMaterialCacheTest {

    private final CacheManager cacheManager = new CaffeineCacheManager(CacheConfig.KEYSTORES_CACHE);

    private final KeyMaterialCache keyMaterialCache = new KeyMaterialCache(cacheManager);

    private final UUID token = UUID.randomUUID();

    private final CachedKeyMaterial outdated = materialOfVersion(1);

    @Test
    void keepsMaterialAnotherRequestReloaded() {
        // given
        CachedKeyMaterial newer = materialOfVersion(2);
        keystores().put(token, newer);

        // when
        keyMaterialCache.evictIfStillCached(token, outdated);

        // then
        assertSame(newer, keyMaterialCache.kept(token));
    }

    @Test
    void evictsTheOutdatedCopyWhileItIsCached() {
        // given
        keystores().put(token, outdated);

        // when
        keyMaterialCache.evictIfStillCached(token, outdated);

        // then
        assertNull(keyMaterialCache.kept(token));
    }

    private static CachedKeyMaterial materialOfVersion(long version) {
        return new CachedKeyMaterial(Map.of(), Map.of(), "code", new Timestamp(version));
    }

    private Cache keystores() {
        return Objects.requireNonNull(cacheManager.getCache(CacheConfig.KEYSTORES_CACHE));
    }
}
