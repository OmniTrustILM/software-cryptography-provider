package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.RequestAttributeV2;
import com.czertainly.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.czertainly.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.czertainly.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceStatusDto;
import com.czertainly.cp.soft.attribute.TokenInstanceActivationAttributes;
import com.czertainly.cp.soft.dao.entity.TokenInstance;
import com.czertainly.cp.soft.dao.repository.TokenInstanceRepository;
import com.czertainly.cp.soft.exception.TokenInstanceException;
import com.czertainly.cp.soft.service.KeyStoreCacheService;
import com.czertainly.cp.soft.util.KeyStoreUtil;
import com.czertainly.cp.soft.util.SecretsUtil;
import com.czertainly.cp.soft.util.SecretsUtilHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.Security;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Token instance lifecycle. Activation stores the keystore password and deactivation clears
 * it, and both must evict the cached key material so a later operation cannot keep using a
 * keystore the operator has just locked.
 */
class TokenInstanceLifecycleTest {

    private static final String PASSWORD = "activation-code";
    private static final UUID TOKEN_UUID = UUID.fromString("11111111-2222-3333-4444-555555555555");

    private TokenInstanceRepository repository;
    private KeyStoreCacheService keyStoreCacheService;
    private TokenInstanceServiceImpl service;


    private static SecretsUtil previousShared;

    @BeforeAll
    static void prepareCrypto() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        // TokenInstance encrypts through the shared instance, which only Spring publishes.
        // This class has no context, so it publishes its own and puts back whatever was there,
        // leaving any Spring test that runs later with the instance it expects.
        previousShared = SecretsUtilHolder.current();
        SecretsUtil forTest = new SecretsUtil();
        forTest.setEncryptionKey("unit-test-encryption-key");
        SecretsUtilHolder.configure(forTest);
    }

    @AfterAll
    static void restoreShared() {
        SecretsUtilHolder.configure(previousShared);
    }

    @BeforeEach
    void setUp() {
        repository = mock(TokenInstanceRepository.class);
        keyStoreCacheService = mock(KeyStoreCacheService.class);
        service = new TokenInstanceServiceImpl();
        service.setTokenInstanceRepository(repository);
        service.setKeyStoreCacheService(keyStoreCacheService);
        ReflectionTestUtils.setField(service, "deleteOnRemove", false);
    }

    private static TokenInstance token(boolean activated) {
        TokenInstance token = new TokenInstance();
        token.setUuid(TOKEN_UUID);
        token.setName("token");
        token.setData(KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD));
        if (activated) {
            token.setCode(PASSWORD);
        }
        return token;
    }

    @Test
    void noTokensIsReportedAsNullRatherThanAnEmptyList() {
        when(repository.findAll()).thenReturn(List.of());

        assertNull(service.listTokenInstances(), "an empty repository must report null");
        assertFalse(service.containsTokens());
    }

    @Test
    void existingTokensAreMappedToDtos() {
        when(repository.findAll()).thenReturn(List.of(token(false)));

        assertEquals(1, service.listTokenInstances().size());
        assertTrue(service.containsTokens());
    }

    @Test
    void anUnknownTokenIsReportedAsNotFound() {
        when(repository.findByUuid(TOKEN_UUID)).thenReturn(Optional.empty());

        assertThrows(NotFoundException.class, () -> service.getTokenInstance(TOKEN_UUID));
        assertThrows(NotFoundException.class, () -> service.getTokenInstanceEntity(TOKEN_UUID));
        assertThrows(NotFoundException.class, () -> service.getTokenInstanceStatus(TOKEN_UUID));
        assertThrows(NotFoundException.class, () -> service.removeTokenInstance(TOKEN_UUID));
        assertThrows(NotFoundException.class, () -> service.deactivateTokenInstance(TOKEN_UUID));
    }

    @Test
    void aKnownTokenIsReturned() throws NotFoundException {
        when(repository.findByUuid(TOKEN_UUID)).thenReturn(Optional.of(token(false)));

        assertNotNull(service.getTokenInstance(TOKEN_UUID));
        assertEquals(TOKEN_UUID, service.getTokenInstanceEntity(TOKEN_UUID).getUuid());
    }

    @Test
    void statusFollowsWhetherTheActivationCodeIsHeld() throws NotFoundException {
        when(repository.findByUuid(TOKEN_UUID)).thenReturn(Optional.of(token(true)));
        TokenInstanceStatusDto activated = service.getTokenInstanceStatus(TOKEN_UUID);
        assertEquals(TokenInstanceStatus.ACTIVATED, activated.getStatus());

        when(repository.findByUuid(TOKEN_UUID)).thenReturn(Optional.of(token(false)));
        TokenInstanceStatusDto deactivated = service.getTokenInstanceStatus(TOKEN_UUID);
        assertEquals(TokenInstanceStatus.DEACTIVATED, deactivated.getStatus());
    }

    @Test
    void removeKeepsTheRowWhenDeleteOnRemoveIsOff() throws NotFoundException {
        TokenInstance existing = token(true);
        when(repository.findByUuid(TOKEN_UUID)).thenReturn(Optional.of(existing));

        service.removeTokenInstance(TOKEN_UUID);

        verify(repository, never()).delete(existing);
        // The cache still has to be dropped, or the keystore would remain usable.
        verify(keyStoreCacheService).evictAfterCommit(TOKEN_UUID);
    }

    @Test
    void removeDeletesTheRowWhenDeleteOnRemoveIsOn() throws NotFoundException {
        ReflectionTestUtils.setField(service, "deleteOnRemove", true);
        TokenInstance existing = token(true);
        when(repository.findByUuid(TOKEN_UUID)).thenReturn(Optional.of(existing));

        service.removeTokenInstance(TOKEN_UUID);

        verify(repository).delete(existing);
        verify(keyStoreCacheService).evictAfterCommit(TOKEN_UUID);
    }

    @Test
    void activationStoresTheCodeAndDropsTheCache() throws Exception {
        TokenInstance existing = token(false);
        when(repository.findByUuid(TOKEN_UUID)).thenReturn(Optional.of(existing));

        service.activateTokenInstance(TOKEN_UUID, activationAttributes(PASSWORD));

        assertEquals(PASSWORD, existing.getCode());
        verify(repository).save(existing);
        verify(keyStoreCacheService).evictAfterCommit(TOKEN_UUID);
    }

    @Test
    void activationWithTheWrongCodeIsRefusedAndChangesNothing() {
        TokenInstance existing = token(false);
        when(repository.findByUuid(TOKEN_UUID)).thenReturn(Optional.of(existing));

        List<RequestAttribute> attributes = activationAttributes("wrong-code");
        TokenInstanceException thrown = assertThrows(TokenInstanceException.class,
                () -> service.activateTokenInstance(TOKEN_UUID, attributes));
        assertTrue(thrown.getMessage().contains("Cannot activate token"));

        assertNull(existing.getCode(), "a failed activation must not store the code");
        verify(repository, never()).save(existing);
    }

    @Test
    void activatingAnAlreadyActiveTokenIsRefused() {
        when(repository.findByUuid(TOKEN_UUID)).thenReturn(Optional.of(token(true)));

        List<RequestAttribute> attributes = activationAttributes(PASSWORD);
        TokenInstanceException thrown = assertThrows(TokenInstanceException.class,
                () -> service.activateTokenInstance(TOKEN_UUID, attributes));
        assertEquals("Token instance already activated", thrown.getMessage());
    }

    @Test
    void deactivationClearsTheCodeAndDropsTheCache() throws Exception {
        TokenInstance existing = token(true);
        when(repository.findByUuid(TOKEN_UUID)).thenReturn(Optional.of(existing));

        service.deactivateTokenInstance(TOKEN_UUID);

        assertNull(existing.getCode());
        verify(repository).save(existing);
        verify(keyStoreCacheService).evictAfterCommit(TOKEN_UUID);
    }

    @Test
    void deactivatingAnInactiveTokenIsRefused() {
        when(repository.findByUuid(TOKEN_UUID)).thenReturn(Optional.of(token(false)));

        TokenInstanceException thrown = assertThrows(TokenInstanceException.class,
                () -> service.deactivateTokenInstance(TOKEN_UUID));
        assertEquals("Token instance already deactivated", thrown.getMessage());
    }

    @Test
    void savingATokenAlsoDropsItsCachedKeyMaterial() {
        TokenInstance existing = token(true);

        service.saveTokenInstance(existing);

        verify(repository).save(existing);
        verify(keyStoreCacheService).evictAfterCommit(TOKEN_UUID);
    }

    private static List<RequestAttribute> activationAttributes(String code) {
        RequestAttributeV2 requested = new RequestAttributeV2();
        requested.setName(TokenInstanceActivationAttributes.ATTRIBUTE_DATA_ACTIVATION_CODE);
        requested.setUuid(UUID.fromString(TokenInstanceActivationAttributes.ATTRIBUTE_DATA_ACTIVATION_CODE_UUID));

        SecretAttributeContentV2 content = new SecretAttributeContentV2();
        content.setReference("code");
        content.setData(new SecretAttributeContentData(code));
        requested.setContent(List.of(content));

        return List.of(requested);
    }
}
