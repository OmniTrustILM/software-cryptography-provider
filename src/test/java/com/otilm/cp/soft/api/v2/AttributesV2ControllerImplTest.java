package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackRequestDto;
import com.otilm.api.model.client.connector.v2.attribute.AttributeDefinitionsDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.attribute.TokenInstanceAttributes;
import com.otilm.cp.soft.exception.AttributeDefinitionMissingException;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.testsupport.KeyRequestFixtures;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
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

    private AttributesV2ControllerImpl controller;

    private TokenV2ControllerImpl tokenController;

    private KeyV2ControllerImpl keyController;

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

    @Test
    void answersNoCallback() {
        // given
        // when
        // then
        AttributeCallbackRequestDto request = new AttributeCallbackRequestDto();

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
        assertTrue(names.contains("data_rsaSigScheme"), () -> "got " + names);
        assertTrue(names.contains("data_sigDigest"), () -> "got " + names);
        assertTrue(names.contains("data_rsaEncScheme"), () -> "got " + names);
    }
}
