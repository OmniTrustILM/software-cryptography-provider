package com.otilm.cp.soft.service.impl;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.key.value.CustomKeyValue;
import com.otilm.api.model.connector.cryptography.v2.KeyScopedRequestV2Dto;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import com.otilm.cp.soft.model.CachedKeyData;
import com.otilm.cp.soft.model.CachedKeyMaterial;
import com.otilm.cp.soft.model.OperationKey;
import com.otilm.cp.soft.service.KeyContextService;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Every keystore this connector writes keeps a certificate beside each private key. An uncertified private key is one
 * its token's material does not hold.
 */
class CryptographicOperationsV2ServiceImplTest {

    private KeyContextService keyContextService;
    private CryptographicOperationsV2ServiceImpl service;

    @BeforeEach
    void setUp() {
        keyContextService = mock(KeyContextService.class);
        service = new CryptographicOperationsV2ServiceImpl();
        service.setKeyContextService(keyContextService);
    }

    @Test
    void refusesAnUncertifiedPrivateKey() {
        // given
        KeyScopedRequestV2Dto request = addressing(uncertifiedMldsaKey());

        // when
        // then
        assertThrows(CryptographicOperationException.class, () -> service.signatureAttributes(request));
    }

    private KeyScopedRequestV2Dto addressing(OperationKey key) {
        when(keyContextService.resolveForOperation(any(), any())).thenReturn(key);
        return new KeyScopedRequestV2Dto();
    }

    private static OperationKey uncertifiedMldsaKey() {
        CustomKeyValue value = new CustomKeyValue();
        value.setValues(new HashMap<>(Map.of("level", "3", "prehash", "false")));
        CachedKeyData key = new CachedKeyData(UUID.randomUUID(), UUID.randomUUID(), "uncertified", "uncertified",
                KeyType.PRIVATE_KEY, KeyAlgorithm.MLDSA, KeyFormat.CUSTOM, value, 0, List.of());
        return new OperationKey(key, new CachedKeyMaterial(Map.of(), Map.of(), "code", null));
    }
}
