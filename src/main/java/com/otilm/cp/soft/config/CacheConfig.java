package com.otilm.cp.soft.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableCaching
public class CacheConfig {

    public static final String KEYSTORES_CACHE = "keystores";
    public static final String KEYDATA_CACHE = "keydata";

    @Value("${provider.cache.keystore.ttl-seconds:60}")
    private long keyStoreTtlSeconds;

    @Value("${provider.cache.keystore.max-size:500}")
    private long keyStoreMaxSize;

    @Value("${provider.cache.keydata.ttl-seconds:300}")
    private long keyDataTtlSeconds;

    @Value("${provider.cache.keydata.max-size:10000}")
    private long keyDataMaxSize;

    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager manager = new CaffeineCacheManager();
        manager.registerCustomCache(KEYSTORES_CACHE,
                Caffeine.newBuilder()
                        .expireAfterWrite(keyStoreTtlSeconds, TimeUnit.SECONDS)
                        .maximumSize(keyStoreMaxSize)
                        .recordStats()
                        .build());
        manager.registerCustomCache(KEYDATA_CACHE,
                Caffeine.newBuilder()
                        .expireAfterWrite(keyDataTtlSeconds, TimeUnit.SECONDS)
                        .maximumSize(keyDataMaxSize)
                        .recordStats()
                        .build());
        return manager;
    }
}
