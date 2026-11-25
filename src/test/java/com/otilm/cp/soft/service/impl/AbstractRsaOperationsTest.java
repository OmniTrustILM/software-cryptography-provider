package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.value.SpkiKeyValue;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.config.CacheConfig;
import com.otilm.cp.soft.dao.repository.KeyDataRepository;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class AbstractRsaOperationsTest extends AbstractCryptographicOperationsTest {

    private final Map<Integer, RsaPair> keys = new HashMap<>();
    private final List<UUID> fixtureTokens = new ArrayList<>();
    private RsaPair otherRsa2048;

    @Autowired
    private KeyDataRepository keyDataRepository;
    @Autowired
    private CacheManager cacheManager;
    @Autowired
    private TransactionTemplate transactions;

    @BeforeAll
    void createReadOnlyKeys() throws NotFoundException, GeneralSecurityException {
        for (int size : List.of(1024, 2048, 4096)) {
            keys.put(size, createFixture(size, "test-rsa-" + size));
        }
        otherRsa2048 = createFixture(2048, "other-rsa-2048");
        assertNotEquals(keys.get(2048).publicKey().getModulus(), otherRsa2048.publicKey().getModulus());
    }

    private RsaPair createFixture(int size, String alias) throws NotFoundException, GeneralSecurityException {
        super.setUp();
        fixtureTokens.add(tokenInstance.getUuid());
        return generatePair(size, alias);
    }

    RsaPair newRsaPair(int size, String alias) throws NotFoundException, GeneralSecurityException {
        // The wrong-key-type cases create their own token and pair inside the test transaction.
        super.setUp();
        return generatePair(size, alias);
    }

    private RsaPair generatePair(int size, String alias) throws NotFoundException, GeneralSecurityException {
        CreateKeyRequestDto request = new CreateKeyRequestDto();
        request.setCreateKeyAttributes(buildRsaCreateKeyAttributes(alias, size));
        UUID token = tokenInstance.getUuid();
        KeyPairDataResponseDto generated = keyManagementService.createKeyPair(token, request);
        assertEquals(KeyAlgorithm.RSA, generated.getPrivateKeyData().getKeyData().getAlgorithm());
        assertEquals(KeyAlgorithm.RSA, generated.getPublicKeyData().getKeyData().getAlgorithm());
        SpkiKeyValue spki = (SpkiKeyValue) generated.getPublicKeyData().getKeyData().getValue();
        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory
                .getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(spki.getValue())));
        assertEquals(size, publicKey.getModulus().bitLength());
        return new RsaPair(token, UUID.fromString(generated.getPrivateKeyData().getUuid()),
                UUID.fromString(generated.getPublicKeyData().getUuid()), publicKey);
    }

    List<RsaPair> keysFor(int size, boolean switchKeys) {
        RsaPair pair = keys.get(size);
        return switchKeys ? List.of(pair, otherRsa2048) : List.of(pair);
    }

    @Override
    @BeforeEach
    void setUp() {
        // Every case still opens its keystore and reads both key rows on first use.
        Cache tokens = Objects.requireNonNull(cacheManager.getCache(CacheConfig.KEYSTORES_CACHE));
        Cache rows = Objects.requireNonNull(cacheManager.getCache(CacheConfig.KEYDATA_CACHE));
        for (RsaPair pair : keys.values()) {
            pair.evict(tokens, rows);
        }
        if (otherRsa2048 != null) {
            otherRsa2048.evict(tokens, rows);
        }
    }

    @AfterAll
    void removeFixtureTokens() {
        setUp();
        transactions.executeWithoutResult(status -> {
            for (UUID token : fixtureTokens) {
                keyDataRepository.deleteAll(keyDataRepository.findAllByTokenInstanceUuid(token));
                tokenInstanceRepository.findByUuid(token).ifPresent(tokenInstanceRepository::delete);
            }
        });
    }

    record RsaPair(UUID tokenUuid, UUID privateUuid, UUID publicUuid, RSAPublicKey publicKey) {
        void evict(Cache tokens, Cache rows) {
            tokens.evict(tokenUuid);
            rows.evict(privateUuid);
            rows.evict(publicUuid);
        }
    }

    private List<RequestAttribute> buildRsaCreateKeyAttributes(String alias, int keySize) {
        List<RequestAttribute> attributes = new ArrayList<>();
        attributes.add(buildAliasAttribute(alias));
        attributes.add(buildAlgorithmAttribute(KeyAlgorithm.RSA));

        RequestAttributeV2 rsaKeySize = new RequestAttributeV2();
        rsaKeySize.setName(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE);
        rsaKeySize.setContentType(AttributeContentType.INTEGER);
        rsaKeySize.setContent(List.of(new IntegerAttributeContentV2("RSA_" + keySize, keySize)));
        attributes.add(rsaKeySize);

        return attributes;
    }
}
