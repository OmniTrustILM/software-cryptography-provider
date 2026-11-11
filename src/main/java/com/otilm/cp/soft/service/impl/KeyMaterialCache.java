package com.otilm.cp.soft.service.impl;

import com.otilm.cp.soft.config.CacheConfig;
import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.exception.TokenInstanceException;
import com.otilm.cp.soft.model.CachedKeyMaterial;
import com.otilm.cp.soft.util.KeyStoreUtil;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.stereotype.Component;

/**
 * Holds the key material extracted from a token's keystore.
 *
 * <p>
 * Extracting it means deriving a key from the token's code over the whole of the keystore, which is far too much to do
 * for every request, so what comes out is kept. Whether what is kept is still what the token holds is not decided here:
 * this only keeps it and gives it up when asked.
 * </p>
 */
@Component
public class KeyMaterialCache {

    private static final Logger logger = LoggerFactory.getLogger(KeyMaterialCache.class);

    private final CacheManager cacheManager;

    public KeyMaterialCache(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    /**
     * The material of the given token, extracted from its keystore the first time it is asked for.
     *
     * @param tokenInstanceUuid the token, which is what the material is kept under
     * @param tokenInstance the token's row, which the material is extracted from
     * @return the material
     */
    @Cacheable(value = CacheConfig.KEYSTORES_CACHE, key = "#tokenInstanceUuid", sync = true)
    public CachedKeyMaterial of(UUID tokenInstanceUuid, TokenInstance tokenInstance) {
        logger.debug("Cache miss — loading key material for token instance {} from database", tokenInstanceUuid);

        String code = tokenInstance.getCode();
        if (code == null) {
            throw new TokenInstanceException("Token is not activated.");
        }

        KeyStore ks = KeyStoreUtil.loadKeystore(tokenInstance.getData(), code);

        Map<String, PrivateKey> privateKeys = new HashMap<>();
        Map<String, PublicKey> publicKeys = new HashMap<>();

        try {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                extractAliasKeyMaterial(ks, aliases.nextElement(), code.toCharArray(), privateKeys, publicKeys);
            }
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot enumerate KeyStore aliases", e);
        }

        return new CachedKeyMaterial(Collections.unmodifiableMap(privateKeys), Collections.unmodifiableMap(publicKeys),
                code, tokenInstance.getTimestamp());
    }

    /** The material kept for the token, or {@code null} where none is kept. */
    public CachedKeyMaterial kept(UUID tokenInstanceUuid) {
        return keystores().get(tokenInstanceUuid, CachedKeyMaterial.class);
    }

    /**
     * Evicts the token's material only while the cache still holds the given outdated copy. Material another request
     * has reloaded in the meantime stays, so concurrent requests reload it only once.
     */
    public void evictIfStillCached(UUID tokenInstanceUuid, CachedKeyMaterial outdated) {
        keystores().getNativeCache().asMap().remove(tokenInstanceUuid, outdated);
    }

    /** Gives up what is kept for a token, so the next request for it takes the material out afresh. */
    @CacheEvict(value = CacheConfig.KEYSTORES_CACHE, key = "#tokenInstanceUuid")
    public void forget(UUID tokenInstanceUuid) {
        logger.debug("Evicted cached key material for token instance {}", tokenInstanceUuid);
    }

    private CaffeineCache keystores() {
        return (CaffeineCache) Objects.requireNonNull(cacheManager.getCache(CacheConfig.KEYSTORES_CACHE));
    }

    private void extractAliasKeyMaterial(KeyStore ks, String alias, char[] password,
            Map<String, PrivateKey> privateKeys, Map<String, PublicKey> publicKeys) {
        try {
            Key key = ks.getKey(alias, password);
            if (key instanceof PrivateKey pk) {
                privateKeys.put(alias, pk);
            }
            Certificate cert = ks.getCertificate(alias);
            if (cert != null) {
                publicKeys.put(alias, cert.getPublicKey());
            }
        } catch (UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Cannot recover key for alias '" + alias + "'", e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Cannot access key material for alias '" + alias + "'", e);
        }
    }
}
