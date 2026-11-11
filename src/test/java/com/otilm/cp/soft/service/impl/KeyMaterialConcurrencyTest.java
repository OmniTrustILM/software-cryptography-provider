package com.otilm.cp.soft.service.impl;

import com.otilm.cp.soft.config.CacheConfig;
import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.dao.repository.TokenInstanceRepository;
import com.otilm.cp.soft.model.CachedKeyMaterial;
import com.otilm.cp.soft.service.KeyStoreCacheService;
import com.otilm.cp.soft.util.KeyStoreUtil;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

/**
 * Requests arriving while a token's material is being extracted share that extraction. Each extraction derives a key
 * from the token's code.
 */
@SpringBootTest
class KeyMaterialConcurrencyTest {

    private static final String CODE = "123";

    private static final int REQUESTS = 8;

    /** Shorter than an extraction. Later requests therefore arrive while the first is still under way. */
    private static final long ARRIVAL_GAP_MILLIS = 10;

    private KeyStoreCacheService keyStoreCacheService;

    private TokenInstanceRepository tokenInstanceRepository;

    private CacheManager cacheManager;

    private TokenInstance tokenInstance;

    private UUID tokenUuid;

    @Autowired
    void setKeyStoreCacheService(KeyStoreCacheService keyStoreCacheService) {
        this.keyStoreCacheService = keyStoreCacheService;
    }

    @Autowired
    void setTokenInstanceRepository(TokenInstanceRepository tokenInstanceRepository) {
        this.tokenInstanceRepository = tokenInstanceRepository;
    }

    @Autowired
    void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    @BeforeEach
    void setUp() {
        tokenInstance = new TokenInstance();
        tokenInstance.setCode(CODE);
        tokenInstance.setData(KeyStoreUtil.createNewKeystore("PKCS12", CODE));
        tokenInstance = tokenInstanceRepository.save(tokenInstance);
        tokenUuid = tokenInstance.getUuid();
    }

    @AfterEach
    void tearDown() {
        tokenInstanceRepository.delete(tokenInstance);
        keystores().evict(tokenUuid);
    }

    @Test
    void requestsFindingNothingKeptShareOneExtraction() throws Exception {
        // given
        keyStoreCacheService.loadKeyMaterial(tokenUuid);
        keystores().evict(tokenUuid);

        // when
        Set<CachedKeyMaterial> served = loadedOneAfterAnother();

        // then
        assertEquals(1, served.size(), "every request must be served the material one of them extracted");
    }

    @Test
    void requestsFindingMaterialOlderThanTheTokenShareOneExtraction() throws Exception {
        // given
        keyStoreCacheService.loadKeyMaterial(tokenUuid);
        CachedKeyMaterial outdated = new CachedKeyMaterial(Map.of(), Map.of(), CODE, new Timestamp(0));
        keystores().put(tokenUuid, outdated);

        // when
        Set<CachedKeyMaterial> served = loadedOneAfterAnother();

        // then
        assertEquals(1, served.size(), "every request must be served the material one of them extracted");
        assertNotSame(outdated, served.iterator().next(), "material older than the token must be extracted again");
    }

    private Set<CachedKeyMaterial> loadedOneAfterAnother() throws Exception {
        List<Future<CachedKeyMaterial>> answers = new ArrayList<>();
        try (ScheduledExecutorService threads = Executors.newScheduledThreadPool(REQUESTS)) {
            for (int arrival = 0; arrival < REQUESTS; arrival++) {
                answers
                        .add(threads
                                .schedule(() -> keyStoreCacheService.loadKeyMaterial(tokenUuid),
                                        arrival * ARRIVAL_GAP_MILLIS, TimeUnit.MILLISECONDS));
            }
        }
        Set<CachedKeyMaterial> served = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Future<CachedKeyMaterial> answer : answers) {
            served.add(answer.get());
        }
        return served;
    }

    private Cache keystores() {
        return Objects.requireNonNull(cacheManager.getCache(CacheConfig.KEYSTORES_CACHE));
    }
}
