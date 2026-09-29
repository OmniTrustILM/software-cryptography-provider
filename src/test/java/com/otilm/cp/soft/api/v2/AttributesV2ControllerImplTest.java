package com.otilm.cp.soft.api.v2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackRequestDto;
import com.otilm.api.model.client.connector.v2.attribute.AttributeDefinitionsDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import com.otilm.cp.soft.api.CallbackController;
import com.otilm.cp.soft.attribute.EcdsaKeyAttributes;
import com.otilm.cp.soft.attribute.FalconKeyAttributes;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.attribute.KeySpecV2Attributes;
import com.otilm.cp.soft.attribute.MLDSAKeyAttributes;
import com.otilm.cp.soft.attribute.MLKEMAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.attribute.SLHDSAKeyAttributes;
import com.otilm.cp.soft.attribute.TokenInstanceAttributes;
import com.otilm.cp.soft.exception.AttributeDefinitionMissingException;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The V2 attributes interface publishes every definition this connector uses, so the platform can cache them and look
 * one up on its own rather than having to know which operation would return it.
 */
@SpringBootTest
class AttributesV2ControllerImplTest {

    /** Writes a definition the way the platform receives it. */
    private static final ObjectMapper AS_PUBLISHED = new ObjectMapper();

    private AttributesV2ControllerImpl controller;

    private TokenV2ControllerImpl tokenController;

    private KeyV2ControllerImpl keyController;

    private CallbackController v1Callback;

    @Autowired
    void setController(AttributesV2ControllerImpl controller) {
        this.controller = controller;
    }

    @Autowired
    void setTokenController(TokenV2ControllerImpl tokenController) {
        this.tokenController = tokenController;
    }

    @Autowired
    void setKeyController(KeyV2ControllerImpl keyController) {
        this.keyController = keyController;
    }

    @Autowired
    void setV1Callback(CallbackController v1Callback) {
        this.v1Callback = v1Callback;
    }

    @Test
    void publishesEveryDefinitionWithTheBuildThatDefinedThem() {
        // given
        // when
        AttributeDefinitionsDto definitions = controller.listDefinitions(null);

        // then
        assertNotNull(definitions.getConnectorVersion());
        assertFalse(definitions.getDefinitions().isEmpty());
    }

    /** A definition appearing twice would be cached twice and could drift between the copies. */
    @Test
    void publishesEachDefinitionOnce() {
        // given
        // when
        List<String> uuids = controller
                .listDefinitions(null)
                .getDefinitions()
                .stream()
                .map(BaseAttribute::getUuid)
                .toList();

        // then
        assertEquals(uuids.size(), uuids.stream().distinct().count(), () -> "duplicated definitions in " + uuids);
    }

    /** The interfaces ask for them one at a time as well as together, so each has to be reachable on its own. */
    @Test
    void answersWithEveryDefinitionItPublishesByItsIdentifier() {
        // given
        List<BaseAttribute> published = controller.listDefinitions(null).getDefinitions();

        // when
        // then
        for (BaseAttribute attribute : published) {
            assertEquals(attribute.getName(), controller.getDefinition(UUID.fromString(attribute.getUuid())).getName(),
                    () -> attribute.getName() + " cannot be reached by its own identifier");
        }
    }

    @Test
    void narrowsTheAnswerToTheDefinitionsAskedFor() {
        // given
        UUID alias = UUID.fromString(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS_UUID);

        // when
        AttributeDefinitionsDto definitions = controller.listDefinitions(List.of(alias));

        // then
        assertEquals(1, definitions.getDefinitions().size());
        assertEquals(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS, definitions.getDefinitions().get(0).getName());
    }

    /** Asking about several at once must not fail because one of them is unknown here. */
    @Test
    void leavesOutADefinitionItDoesNotPublish() {
        // given
        UUID alias = UUID.fromString(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS_UUID);

        // when
        AttributeDefinitionsDto definitions = controller.listDefinitions(List.of(alias, UUID.randomUUID()));

        // then
        assertEquals(1, definitions.getDefinitions().size());
    }

    @Test
    void answersOneDefinitionByItsIdentifier() {
        // given
        UUID algorithm = UUID.fromString(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM_UUID);

        // when
        BaseAttribute definition = controller.getDefinition(algorithm);

        // then
        assertEquals(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, definition.getName());
    }

    @Test
    void reservedSignatureAlgorithmResolvesByItsIdentifier() {
        BaseAttribute definition = controller.getDefinition(SignatureAlgorithmAttribute.ATTRIBUTE_UUID);

        assertEquals(SignatureAlgorithmAttribute.NAME, definition.getName());
    }

    @Test
    void refusesADefinitionItDoesNotPublish() {
        // given
        UUID unknown = UUID.randomUUID();

        // when
        // then
        assertThrows(AttributeDefinitionMissingException.class, () -> controller.getDefinition(unknown));
    }

    /**
     * A token context asks for different attributes depending on whether a token exists yet, and every one of them has
     * to resolve here. Once a token exists the context offers the choice between an existing token and a new one.
     */
    @Test
    void resolvesEveryAttributeATokenContextCanAskFor() {
        // given
        List<BaseAttribute> asked = new ArrayList<>(TokenInstanceAttributes.getNewTokenAttributes());
        asked.add(TokenInstanceAttributes.buildInitialInfo());
        asked.add(TokenInstanceAttributes.buildOptions());
        asked.add(TokenInstanceAttributes.buildGroupBasedOnSelect());
        asked.add(TokenInstanceAttributes.buildDataSelectExistingToken(List.of()));

        // when
        // then
        for (BaseAttribute attribute : asked) {
            UUID uuid = UUID.fromString(attribute.getUuid());
            assertEquals(attribute.getName(), controller.getDefinition(uuid).getName());
        }
    }

    /** Whatever the token endpoint publishes right now must resolve, whichever of those two states the token is in. */
    @Test
    void resolvesEveryAttributeTheTokenEndpointPublishes() {
        // given
        List<BaseAttribute> published = tokenController.listTokenAttributes();

        // when
        // then
        assertFalse(published.isEmpty(), "the token endpoint must ask for something");
        for (BaseAttribute attribute : published) {
            UUID uuid = UUID.fromString(attribute.getUuid());
            assertEquals(attribute.getName(), controller.getDefinition(uuid).getName());
        }
    }

    /**
     * A caller reads the metadata identifiers off the key it was just given, so every one of them has to resolve here.
     * The key handles are what a later request addresses the key by, which makes their definitions part of the contract
     * as much as the create attributes are.
     */
    @Test
    void resolvesTheMetadataPublishedOnAKeyItCreated() {
        // given
        CreateKeyRequestV2Dto request = KeyRequestFixtures
                .rsaKeyPair(TokenContextFixtures.uniqueName("v2-meta"), "key-" + System.nanoTime());
        KeyPairDataResponseV2Dto created = (KeyPairDataResponseV2Dto) keyController.createKey(request).getBody();
        assertNotNull(created);

        List<MetadataAttribute> published = new ArrayList<>(created.getPublicKeyData().getKeyMeta());
        published.addAll(created.getPrivateKeyData().getKeyMeta());

        // when
        // then
        assertFalse(published.isEmpty(), "a created key must publish the handles addressing it");
        for (MetadataAttribute attribute : published) {
            UUID uuid = UUID.fromString(attribute.getUuid());
            assertEquals(attribute.getName(), controller.getDefinition(uuid).getName());
        }
    }

    static Stream<Arguments> keySpecifications() {
        return Stream
                .of(Arguments.of(KeyAlgorithm.RSA, List.of(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE)),
                        Arguments.of(KeyAlgorithm.ECDSA, List.of(EcdsaKeyAttributes.ATTRIBUTE_DATA_ECDSA_CURVE)),
                        Arguments.of(KeyAlgorithm.FALCON, List.of()),
                        Arguments.of(KeyAlgorithm.MLDSA, List.of(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_LEVEL)),
                        Arguments
                                .of(KeyAlgorithm.SLHDSA,
                                        List
                                                .of(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY,
                                                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE)),
                        Arguments.of(KeyAlgorithm.MLKEM, List.of(MLKEMAttributes.ATTRIBUTE_DATA_MLKEM_LEVEL)));
    }

    /** V2 leaves out every choice beyond the parameter sets a platform signature algorithm names. */
    @ParameterizedTest(name = "{0}")
    @MethodSource("keySpecifications")
    void answersTheKeySpecificationOfTheChosenAlgorithm(KeyAlgorithm algorithm, List<String> asked) {
        // given
        AttributeCallbackRequestDto request = keySpecification(algorithm);

        // when
        List<BaseAttribute> children = controller.callback(request).getAttributes();

        // then
        assertEquals(asked, children.stream().map(BaseAttribute::getName).toList());
    }

    /**
     * The platform keeps one definition per identifier for a connector, whichever interface published it, so a child
     * that differed from V1's under the same identifier would replace it for V1 callers too.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("keySpecifications")
    void answersOnlyDefinitionsV1PublishesUnderTheSameIdentifiers(KeyAlgorithm algorithm, List<String> asked)
            throws JsonProcessingException {
        // given
        Map<String, String> v1 = new HashMap<>();
        for (BaseAttribute attribute : v1Callback.getKeySpecAttributes(algorithm)) {
            v1.put(attribute.getUuid(), AS_PUBLISHED.writeValueAsString(attribute));
        }

        // when
        List<BaseAttribute> children = controller.callback(keySpecification(algorithm)).getAttributes();

        // then
        for (BaseAttribute child : children) {
            assertEquals(v1.get(child.getUuid()), AS_PUBLISHED.writeValueAsString(child), child::getName);
        }
    }

    @Test
    void answersNoKeySpecificationBeforeAnAlgorithmIsChosen() {
        // given
        AttributeCallbackRequestDto request = new AttributeCallbackRequestDto();
        request.setAttributeUuid(UUID.fromString(KeySpecV2Attributes.ATTRIBUTE_GROUP_KEY_SPEC_UUID));
        request.setCurrentAttributes(List.of());

        // when
        List<BaseAttribute> children = controller.callback(request).getAttributes();

        // then
        assertTrue(children.isEmpty());
    }

    @Test
    void refusesACallbackForAnAttributeItDoesNotPublish() {
        // given
        AttributeCallbackRequestDto request = new AttributeCallbackRequestDto();
        request.setAttributeUuid(UUID.randomUUID());

        // when
        // then
        assertThrows(AttributeDefinitionMissingException.class, () -> controller.callback(request));
    }

    @Test
    void refusesACallbackForAnAttributeNoCallbackResolves() {
        // given
        AttributeCallbackRequestDto request = new AttributeCallbackRequestDto();
        request.setAttributeUuid(UUID.fromString(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS_UUID));

        // when
        // then
        assertThrows(NotSupportedException.class, () -> controller.callback(request));
    }

    /** The operation schemas are part of the registry, so a caller can read them without performing an operation. */
    @Test
    void publishesWhatTheOperationsNeedToBeTold() {
        // given
        // when
        List<String> names = controller
                .listDefinitions(null)
                .getDefinitions()
                .stream()
                .map(BaseAttribute::getName)
                .toList();

        // then
        assertTrue(names.contains(SignatureAlgorithmAttribute.NAME), () -> "got " + names);
        assertTrue(names.contains("data_rsaEncScheme"), () -> "got " + names);
        assertFalse(names.contains("data_rsaSigScheme"), () -> "got " + names);
        assertFalse(names.contains("data_sigDigest"), () -> "got " + names);
    }

    @Test
    void offersEverySignatureAlgorithmAKeyCanOffer() {
        // given
        UUID uuid = SignatureAlgorithmAttribute.ATTRIBUTE_UUID;

        // when
        DataAttributeV3 definition = (DataAttributeV3) controller.getDefinition(uuid);

        // then
        assertEquals(List
                .of("SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "SHA256withRSAandMGF1", "SHA384withRSAandMGF1",
                        "SHA512withRSAandMGF1", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "FALCON-1024",
                        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128F",
                        "SLH-DSA-SHA2-192S", "SLH-DSA-SHA2-192F", "SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256F"),
                definition.getContent().stream().map(content -> (String) content.getData()).toList());
    }

    @Test
    void publishesOnlyTheKeySpecificationV2Offers() {
        // given
        // when
        List<String> names = controller
                .listDefinitions(null)
                .getDefinitions()
                .stream()
                .map(BaseAttribute::getName)
                .toList();

        // then
        assertTrue(names.contains(KeySpecV2Attributes.ATTRIBUTE_GROUP_KEY_SPEC), () -> "got " + names);
        for (String left : List
                .of(KeyAttributes.ATTRIBUTE_GROUP_KEY_SPEC, FalconKeyAttributes.ATTRIBUTE_DATA_FALCON_DEGREE,
                        MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_PREHASH, SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_HASH,
                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_PREHASH)) {
            assertFalse(names.contains(left), () -> left + " is V1's alone, got " + names);
        }
    }

    private static AttributeCallbackRequestDto keySpecification(KeyAlgorithm algorithm) {
        AttributeCallbackRequestDto request = new AttributeCallbackRequestDto();
        request.setAttributeUuid(UUID.fromString(KeySpecV2Attributes.ATTRIBUTE_GROUP_KEY_SPEC_UUID));
        request
                .setCurrentAttributes(List
                        .of(TokenContextFixtures
                                .string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, algorithm.getCode())));
        return request;
    }
}
