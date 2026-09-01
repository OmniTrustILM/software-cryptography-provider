package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.config.CacheConfig;
import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.dao.repository.KeyDataRepository;
import com.otilm.cp.soft.dao.repository.TokenInstanceRepository;
import com.otilm.cp.soft.exception.TokenInstanceException;
import com.otilm.cp.soft.service.KeyDataCacheService;
import com.otilm.cp.soft.service.KeyManagementService;
import com.otilm.cp.soft.service.KeyStoreCacheService;
import com.otilm.cp.soft.service.TokenInstanceService;
import com.otilm.cp.soft.util.KeyStoreUtil;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Verifies cache-invalidation semantics for the {@code keystores} and {@code keydata} caches.
 *
 * <p>
 * This class is intentionally <strong>not</strong> annotated with {@code @Transactional}.
 */
@SpringBootTest
class CacheInvalidationTest {

    private static final String PASSWORD = "123";
    private static final int RSA_KEY_SIZE = 2048;

    @Autowired
    private KeyManagementService keyManagementService;
    @Autowired
    private KeyStoreCacheService keyStoreCacheService;
    @Autowired
    private KeyDataCacheService keyDataCacheService;
    @Autowired
    private TokenInstanceService tokenInstanceService;
    @Autowired
    private TokenInstanceRepository tokenInstanceRepository;
    @Autowired
    private KeyDataRepository keyDataRepository;
    @Autowired
    private CacheManager cacheManager;

    private TokenInstance tokenInstance;

    @BeforeEach
    void setUp() {
        tokenInstance = new TokenInstance();
        tokenInstance.setCode(PASSWORD);
        tokenInstance.setData(KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD));
        // save() runs in its own committed transaction (no surrounding test transaction)
        tokenInstanceRepository.save(tokenInstance);
    }

    @AfterEach
    void tearDown() {
        keyDataRepository.deleteAll();
        tokenInstanceRepository.deleteAll();
        Objects.requireNonNull(cacheManager.getCache(CacheConfig.KEYSTORES_CACHE)).clear();
        Objects.requireNonNull(cacheManager.getCache(CacheConfig.KEYDATA_CACHE)).clear();
    }

    // -----------------------------------------------------------------------
    // Keystore cache — eviction on destroyKey (private key path)
    // -----------------------------------------------------------------------

    /**
     * After the private key is destroyed, the keystore cache entry for the owning token instance must be evicted so
     * that the next access re-reads a consistent keystore from the database.
     */
    @Test
    void destroyPrivateKey_shouldEvictKeystoreCache() throws NotFoundException {
        UUID tokenUuid = tokenInstance.getUuid();

        // Create key pair — commits; saveTokenInstance evicts the cache
        KeyPairDataResponseDto created = keyManagementService.createKeyPair(tokenUuid, buildRsa2048Request("ks-evict"));
        UUID privateKeyUuid = UUID.fromString(created.getPrivateKeyData().getUuid());

        // Warm the keystore cache
        keyStoreCacheService.loadKeyMaterial(tokenUuid);
        assertCacheHit(CacheConfig.KEYSTORES_CACHE, tokenUuid);

        // Destroy the private key — commits; removeKeyFromKeyStore → saveTokenInstance → evictAfterCommit
        keyManagementService.destroyKey(tokenUuid, privateKeyUuid);

        assertCacheMiss(CacheConfig.KEYSTORES_CACHE, tokenUuid);
    }

    // -----------------------------------------------------------------------
    // Keystore cache — eviction on deactivateTokenInstance
    // -----------------------------------------------------------------------

    /**
     * Deactivating a token instance nulls its activation code and must evict the keystore cache so that subsequent
     * calls cannot use stale key material.
     */
    @Test
    void deactivateTokenInstance_shouldEvictKeystoreCache() throws NotFoundException {
        UUID tokenUuid = tokenInstance.getUuid();

        // Warm the keystore cache
        keyStoreCacheService.loadKeyMaterial(tokenUuid);
        assertCacheHit(CacheConfig.KEYSTORES_CACHE, tokenUuid);

        // Deactivate — commits; evictAfterCommit is scheduled inside deactivateTokenInstance
        tokenInstanceService.deactivateTokenInstance(tokenUuid);

        assertCacheMiss(CacheConfig.KEYSTORES_CACHE, tokenUuid);
    }

    // -----------------------------------------------------------------------
    // Keydata cache — eviction on destroyKey
    // -----------------------------------------------------------------------

    /**
     * After a key is destroyed, its keydata cache entry must be evicted so that a subsequent getCachedKeyData call hits
     * the database and throws NotFoundException rather than serving a stale record.
     */
    @Test
    void destroyKey_shouldEvictKeydataCache() throws NotFoundException {
        UUID tokenUuid = tokenInstance.getUuid();

        // Create key pair so we have a persisted private-key record
        KeyPairDataResponseDto created = keyManagementService.createKeyPair(tokenUuid, buildRsa2048Request("kd-evict"));
        UUID privateKeyUuid = UUID.fromString(created.getPrivateKeyData().getUuid());

        // Warm the keydata cache for the private key
        keyDataCacheService.getCachedKeyData(privateKeyUuid);
        assertCacheHit(CacheConfig.KEYDATA_CACHE, privateKeyUuid);

        // Destroy the private key — commits; keyDataCacheService.evictAfterCommit fires
        keyManagementService.destroyKey(tokenUuid, privateKeyUuid);

        assertCacheMiss(CacheConfig.KEYDATA_CACHE, privateKeyUuid);
    }

    // -----------------------------------------------------------------------
    // NotFoundException must NOT be cached
    // -----------------------------------------------------------------------

    /**
     * A {@link NotFoundException} thrown by {@code loadKeyMaterial} must not be cached.
     */
    @Test
    void keystoreLoadMiss_notFoundExceptionIsNotCached() {
        UUID nonExistentUuid = UUID.randomUUID();

        // First call: no token instance in DB or cache — must throw
        assertThrows(NotFoundException.class, () -> keyStoreCacheService.loadKeyMaterial(nonExistentUuid));

        // The cache must remain empty for this key (exception was not cached)
        assertCacheMiss(CacheConfig.KEYSTORES_CACHE, nonExistentUuid);
    }

    // -----------------------------------------------------------------------
    // evictAfterCommit — outside-transaction path
    // -----------------------------------------------------------------------

    /**
     * When {@code evictAfterCommit} is called with no active transaction, it must evict immediately rather than
     * scheduling a post-commit callback.
     */
    @Test
    void keystoreEvictAfterCommit_outsideTransaction_evictsImmediately() throws NotFoundException {
        UUID tokenUuid = tokenInstance.getUuid();

        // Warm the cache
        keyStoreCacheService.loadKeyMaterial(tokenUuid);
        assertCacheHit(CacheConfig.KEYSTORES_CACHE, tokenUuid);

        // Called directly from a non-transactional test method — takes the else (immediate) branch
        keyStoreCacheService.evictAfterCommit(tokenUuid);

        assertCacheMiss(CacheConfig.KEYSTORES_CACHE, tokenUuid);
    }

    /**
     * Same immediate-eviction guarantee for the keydata cache.
     */
    @Test
    void keydataEvictAfterCommit_outsideTransaction_evictsImmediately() throws NotFoundException {
        UUID tokenUuid = tokenInstance.getUuid();

        KeyPairDataResponseDto created = keyManagementService
                .createKeyPair(tokenUuid, buildRsa2048Request("kd-outside-tx"));
        UUID privateKeyUuid = UUID.fromString(created.getPrivateKeyData().getUuid());

        // Warm the keydata cache
        keyDataCacheService.getCachedKeyData(privateKeyUuid);
        assertCacheHit(CacheConfig.KEYDATA_CACHE, privateKeyUuid);

        // Called directly from a non-transactional test method — takes the else (immediate) branch
        keyDataCacheService.evictAfterCommit(privateKeyUuid);

        assertCacheMiss(CacheConfig.KEYDATA_CACHE, privateKeyUuid);
    }

    // -----------------------------------------------------------------------
    // loadKeyMaterial — token not activated
    // -----------------------------------------------------------------------

    /**
     * Loading key material for a token whose activation code is null must throw {@link TokenInstanceException} and must
     * not populate the cache.
     */
    @Test
    void loadKeyMaterial_tokenNotActivated_throwsTokenInstanceException() {
        TokenInstance inactiveToken = new TokenInstance();
        inactiveToken.setCode(null);
        inactiveToken.setData(KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD));
        tokenInstanceRepository.save(inactiveToken);

        UUID inactiveUuid = inactiveToken.getUuid();

        assertThrows(TokenInstanceException.class, () -> keyStoreCacheService.loadKeyMaterial(inactiveUuid));

        // Exception must not have been cached
        assertCacheMiss(CacheConfig.KEYSTORES_CACHE, inactiveUuid);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private void assertCacheHit(String cacheName, UUID key) {
        Cache springCache = Objects.requireNonNull(cacheManager.getCache(cacheName));
        assertNotNull(springCache.get(key),
                "Expected a cache HIT for key " + key + " in '" + cacheName + "' but found a miss");
    }

    private void assertCacheMiss(String cacheName, UUID key) {
        Cache springCache = Objects.requireNonNull(cacheManager.getCache(cacheName));
        assertNull(springCache.get(key),
                "Expected a cache MISS for key " + key + " in '" + cacheName + "' but found an entry");
    }

    private CreateKeyRequestDto buildRsa2048Request(String alias) {
        List<RequestAttribute> attrs = new ArrayList<>();

        RequestAttributeV2 aliasAttr = new RequestAttributeV2();
        aliasAttr.setName(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS);
        aliasAttr.setContentType(AttributeContentType.STRING);
        aliasAttr.setContent(List.of(new StringAttributeContentV2(alias)));
        attrs.add(aliasAttr);

        RequestAttributeV2 algoAttr = new RequestAttributeV2();
        algoAttr.setName(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM);
        algoAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 algoContent = new StringAttributeContentV2();
        algoContent.setReference(KeyAlgorithm.RSA.getCode());
        algoContent.setData(KeyAlgorithm.RSA.getCode());
        algoAttr.setContent(List.of(algoContent));
        attrs.add(algoAttr);

        RequestAttributeV2 sizeAttr = new RequestAttributeV2();
        sizeAttr.setName(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE);
        sizeAttr.setContentType(AttributeContentType.INTEGER);
        IntegerAttributeContentV2 sizeContent = new IntegerAttributeContentV2();
        sizeContent.setData(RSA_KEY_SIZE);
        sizeAttr.setContent(List.of(sizeContent));
        attrs.add(sizeAttr);

        CreateKeyRequestDto req = new CreateKeyRequestDto();
        req.setCreateKeyAttributes(attrs);
        return req;
    }
}
