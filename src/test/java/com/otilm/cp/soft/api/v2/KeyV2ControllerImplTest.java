package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.v2.OperationTrackingRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.DestroyKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyCreationResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.OperationConflictException;
import com.otilm.cp.soft.exception.OperationNotTrackedException;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The V2 key lifecycle over the keys this provider already holds: what a key is created from, creating one, and
 * destroying it. Everything completes inline, so nothing is tracked and asynchronous execution is refused.
 */
@SpringBootTest
class KeyV2ControllerImplTest {

    private KeyV2ControllerImpl controller;

    @Autowired
    void setController(KeyV2ControllerImpl controller) {
        this.controller = controller;
    }

    @Test
    void publishesWhatAKeyIsCreatedFrom() {
        // given
        CreateKeyAttributesRequestV2Dto request = new CreateKeyAttributesRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(TokenContextFixtures.uniqueName("v2-key-attrs")));
        request.setTokenProfileAttributes(List.of());
        request.setKeyUsages(Set.of(KeyUsage.SIGN));
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);

        // when
        List<BaseAttribute> attributes = controller.listCreateKeyAttributes(request);

        // then
        assertFalse(attributes.isEmpty());
    }

    @Test
    void createsAKeyPairAndPublishesAHandleForEachHalf() {
        // given
        CreateKeyRequestV2Dto request = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-create"), "key-" + System.nanoTime());

        // when
        ResponseEntity<KeyCreationResponseV2Dto> response = controller.createKey(request);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        KeyPairDataResponseV2Dto created = (KeyPairDataResponseV2Dto) response.getBody();
        assertNotNull(created);
        assertEquals(KeyRequestType.KEY_PAIR, created.getKeyRequestType());
        assertNotNull(created.getPublicKeyData().getKeyData().getPublicKeySpki(), "the public key travels as its SPKI");
        assertFalse(created.getPublicKeyData().getKeyMeta().isEmpty());
        assertFalse(created.getPrivateKeyData().getKeyMeta().isEmpty());
    }

    /**
     * Each half of a pair is a key in its own right and can be destroyed on its own, so a creation identifier can
     * outlive the key it names. Repeating that creation asks for a key that is gone, and no repeat brings it back.
     */
    @Test
    void answersARepeatedCreationOfADestroyedKeyAsGone() {
        // given
        CreateKeyRequestV2Dto request = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-create-destroyed"), "key-" + System.nanoTime());
        KeyPairDataResponseV2Dto created = (KeyPairDataResponseV2Dto) controller.createKey(request).getBody();
        assertNotNull(created);

        DestroyKeyRequestV2Dto destruction = new DestroyKeyRequestV2Dto();
        destruction.setTokenAttributes(request.getTokenAttributes());
        destruction.setKeyMeta(created.getPrivateKeyData().getKeyMeta());
        destruction.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        controller.destroyKey(destruction);

        // when
        // then
        assertThrows(ResourceMissingException.class, () -> controller.createKey(request));
    }

    /** A synchronous response must carry no tracking handle: there is no operation left to track. */
    @Test
    void publishesNoTrackingHandleForWorkItAlreadyFinished() {
        // given
        CreateKeyRequestV2Dto request = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-no-handle"), "key-" + System.nanoTime());

        // when
        KeyCreationResponseV2Dto created = controller.createKey(request).getBody();

        // then
        assertNotNull(created);
        assertTrue(created.getOperationMeta() == null || created.getOperationMeta().isEmpty());
    }

    /** A caller that lost the response repeats the request and must be given the key, not a second one. */
    @Test
    void answersARepeatedCreationWithTheKeyItAlreadyMade() {
        // given
        CreateKeyRequestV2Dto request = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-replay"), "key-" + System.nanoTime());
        KeyPairDataResponseV2Dto first = (KeyPairDataResponseV2Dto) controller.createKey(request).getBody();

        // when
        KeyPairDataResponseV2Dto repeat = (KeyPairDataResponseV2Dto) controller.createKey(request).getBody();

        // then
        assertNotNull(first);
        assertNotNull(repeat);
        assertEquals(first.getPrivateKeyData().getKeyMeta().toString(),
                repeat.getPrivateKeyData().getKeyMeta().toString());
    }

    @Test
    void refusesACreationIdentifierReusedForADifferentRequest() {
        // given
        CreateKeyRequestV2Dto first = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-conflict"), "key-" + System.nanoTime());
        controller.createKey(first);

        CreateKeyRequestV2Dto different = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-conflict-other"), "key-" + System.nanoTime());
        different.setKeyCreationId(first.getKeyCreationId());

        // when
        // then
        assertThrows(OperationConflictException.class, () -> controller.createKey(different));
    }

    /**
     * The token a request addressed stands in for the context that addressed it, so what the request asks for has to be
     * told apart on its own. Two keys under one token differ only in their attributes.
     */
    @Test
    void refusesACreationIdentifierReusedForAnotherKeyUnderTheSameToken() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-conflict-same-token");
        CreateKeyRequestV2Dto first = KeyRequestFixtures.rsaKeyPair(token, "key-" + System.nanoTime());
        controller.createKey(first);

        CreateKeyRequestV2Dto other = KeyRequestFixtures.rsaKeyPair(token, "other-" + System.nanoTime());
        other.setKeyCreationId(first.getKeyCreationId());

        // when
        // then
        assertThrows(OperationConflictException.class, () -> controller.createKey(other));
    }

    @Test
    void refusesAsynchronousExecution() {
        // given
        CreateKeyRequestV2Dto request = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-async"), "key-" + System.nanoTime());
        request.setExecutionMode(OperationExecutionMode.ASYNCHRONOUS);

        // when
        // then
        assertThrows(NotSupportedException.class, () -> controller.createKey(request));
    }

    @Test
    void refusesSecretKeys() {
        // given
        CreateKeyRequestV2Dto request = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-secret"), "key-" + System.nanoTime());
        request.setKeyRequestType(KeyRequestType.SECRET);

        // when
        // then
        assertThrows(NotSupportedException.class, () -> controller.createKey(request));
    }

    @Test
    void destroysTheKeyItsMetadataAddresses() {
        // given
        String token = TokenContextFixtures.uniqueName("v2-destroy");
        CreateKeyRequestV2Dto creation = KeyRequestFixtures.rsaKeyPair(token, "key-" + System.nanoTime());
        KeyPairDataResponseV2Dto created = (KeyPairDataResponseV2Dto) controller.createKey(creation).getBody();
        assertNotNull(created);

        DestroyKeyRequestV2Dto request = destroyRequest(creation.getTokenAttributes(),
                created.getPrivateKeyData().getKeyMeta());

        // when
        ResponseEntity<?> response = controller.destroyKey(request);

        // then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertThrows(ResourceMissingException.class, () -> controller.destroyKey(request),
                "a key destroyed once is gone");
    }

    /** Nothing is ever accepted for asynchronous processing, so nothing is ever tracked. */
    @Test
    void tracksNoOperation() {
        // given
        OperationTrackingRequestV2Dto request = new OperationTrackingRequestV2Dto();

        // when
        // then
        assertThrows(OperationNotTrackedException.class, () -> controller.getCreateKeyStatus(request));
        assertThrows(OperationNotTrackedException.class, () -> controller.cancelCreateKey(request));
        assertThrows(OperationNotTrackedException.class, () -> controller.getDestroyKeyStatus(request));
        assertThrows(OperationNotTrackedException.class, () -> controller.cancelDestroyKey(request));
    }

    private static DestroyKeyRequestV2Dto destroyRequest(List<RequestAttribute> tokenAttributes,
            List<MetadataAttribute> keyMeta) {
        DestroyKeyRequestV2Dto request = new DestroyKeyRequestV2Dto();
        request.setTokenAttributes(tokenAttributes);
        request.setTokenProfileAttributes(List.of());
        request.setKeyUsages(Set.of(KeyUsage.SIGN));
        request.setKeyMeta(keyMeta);
        request.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        return request;
    }
}
