package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.GroupAttributeV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.v2.OperationTrackingRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.DestroyKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyCreationResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.cp.soft.attribute.FalconKeyAttributes;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.attribute.KeySpecV2Attributes;
import com.otilm.cp.soft.attribute.MLDSAKeyAttributes;
import com.otilm.cp.soft.attribute.SLHDSAKeyAttributes;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.OperationConflictException;
import com.otilm.cp.soft.exception.OperationNotTrackedException;
import com.otilm.cp.soft.exception.ParameterUnsupportedException;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);

        // when
        List<BaseAttribute> attributes = controller.listCreateKeyAttributes(request);

        // then
        assertFalse(attributes.isEmpty());
    }

    /** V1's key specification resolves through a V1 callback and offers keys V2 cannot sign with. */
    @Test
    void asksForItsOwnKeySpecificationResolvedThroughTheV2Callback() {
        // given
        CreateKeyAttributesRequestV2Dto request = new CreateKeyAttributesRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(TokenContextFixtures.uniqueName("v2-key-spec")));
        request.setTokenProfileAttributes(List.of());
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);

        // when
        List<BaseAttribute> attributes = controller.listCreateKeyAttributes(request);

        // then
        List<String> names = attributes.stream().map(BaseAttribute::getName).toList();
        assertFalse(names.contains(KeyAttributes.ATTRIBUTE_GROUP_KEY_SPEC), () -> "got " + names);
        GroupAttributeV3 group = (GroupAttributeV3) attributes
                .stream()
                .filter(attribute -> KeySpecV2Attributes.ATTRIBUTE_GROUP_KEY_SPEC.equals(attribute.getName()))
                .findFirst()
                .orElseThrow();
        assertEquals(List.of(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM), group.getAttributeCallback().getDependsOn());
        assertNull(group.getAttributeCallback().getCallbackContext());
    }

    static Stream<Arguments> creationsNoPlatformAlgorithmNames() {
        return Stream
                .of(Arguments
                        .of("Falcon-512",
                                List
                                        .of(algorithm(KeyAlgorithm.FALCON),
                                                stated(FalconKeyAttributes.ATTRIBUTE_DATA_FALCON_DEGREE,
                                                        new IntegerAttributeContentV2("FALCON_512", 512)))),
                        Arguments
                                .of("HashML-DSA-65",
                                        List
                                                .of(algorithm(KeyAlgorithm.MLDSA),
                                                        stated(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_LEVEL,
                                                                new IntegerAttributeContentV2("MLDSA_65", 3)),
                                                        stated(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_PREHASH,
                                                                new BooleanAttributeContentV2(true)))),
                        Arguments
                                .of("SLH-DSA-SHAKE-128S",
                                        slhdsa(stated(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_HASH,
                                                new StringAttributeContentV2("SHAKE256", "SHAKE")))),
                        Arguments
                                .of("HashSLH-DSA-SHA2-128S",
                                        slhdsa(stated(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_PREHASH,
                                                new BooleanAttributeContentV2(true)))));
    }

    /**
     * The key is made before it is refused, so what matters is that the refusal leaves nothing behind: the alias it was
     * made under is still free in a token that already exists.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("creationsNoPlatformAlgorithmNames")
    void refusesToCreateAKeyNoPlatformSignatureAlgorithmNames(String variant, List<RequestAttribute> parameters) {
        // given
        String token = TokenContextFixtures.uniqueName("v2-unsignable-creation");
        controller.createKey(KeyRequestFixtures.rsaKeyPair(token, "key-" + System.nanoTime()));
        String alias = "key-" + System.nanoTime();
        CreateKeyRequestV2Dto refused = KeyRequestFixtures.rsaKeyPair(token, alias);
        List<RequestAttribute> attributes = new ArrayList<>(parameters);
        attributes.add(TokenContextFixtures.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS, alias));
        refused.setCreateKeyAttributes(attributes);

        // when
        assertThrows(ParameterUnsupportedException.class, () -> controller.createKey(refused));

        // then
        assertNotNull(controller.createKey(KeyRequestFixtures.rsaKeyPair(token, alias)).getBody());
    }

    private static List<RequestAttribute> slhdsa(RequestAttribute outsideWhatV2Offers) {
        return List
                .of(algorithm(KeyAlgorithm.SLHDSA),
                        stated(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY,
                                new StringAttributeContentV2("CATEGORY_1", "1")),
                        stated(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE,
                                new StringAttributeContentV2("SMALL", "SMALL")),
                        outsideWhatV2Offers);
    }

    private static RequestAttribute algorithm(KeyAlgorithm algorithm) {
        return TokenContextFixtures.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, algorithm.getCode());
    }

    private static RequestAttribute stated(String name, BaseAttributeContentV2<?> content) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(content));
        return attribute;
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

    @Test
    void namesThePairByItsAlias() {
        // given
        String alias = "key-" + System.nanoTime();
        CreateKeyRequestV2Dto request = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-pair-meta"), alias);

        // when
        KeyPairDataResponseV2Dto created = (KeyPairDataResponseV2Dto) controller.createKey(request).getBody();

        // then
        assertNotNull(created);
        assertNotNull(created.getKeyPairMeta(), "the pair is named");
        assertEquals(Map.of(KeyAttributes.ATTRIBUTE_META_KEY_ALIAS, alias), byName(created.getKeyPairMeta()));
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
        request.setKeyMeta(keyMeta);
        request.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        return request;
    }

    private static Map<String, String> byName(List<MetadataAttribute> metadata) {
        return metadata
                .stream()
                .collect(Collectors
                        .toMap(MetadataAttribute::getName,
                                item -> item.<List<StringAttributeContentV2>>getContent().get(0).getData()));
    }
}
