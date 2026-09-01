package com.czertainly.cp.soft.config;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import java.security.Provider;
import java.security.Security;

@Configuration
@EnableJpaAuditing
@ComponentScan(basePackages = "com.czertainly.cp.soft")
public class ApplicationConfig {
    private static final Logger logger = LoggerFactory.getLogger(ApplicationConfig.class);

    @Bean
    public Provider securityProvider() {
        Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider == null) {
            logger.info("Registering security provider {}.", BouncyCastleProvider.PROVIDER_NAME);
            provider = new BouncyCastleProvider();
            Security.addProvider(provider);
        } else {
            logger.info("Security provider {} already registered.", BouncyCastleProvider.PROVIDER_NAME);
        }
        return provider;
    }

    @Bean
    public Provider securityPqcProvider() {
        Provider pqcProvider = Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME);
        if (pqcProvider == null) {
            logger.info("Registering PQC security provider {}.", BouncyCastlePQCProvider.PROVIDER_NAME);
            pqcProvider = new BouncyCastlePQCProvider();
            Security.addProvider(pqcProvider);
        } else {
            logger.info("PQC security provider {} already registered.", BouncyCastlePQCProvider.PROVIDER_NAME);
        }
        return pqcProvider;
    }
}
