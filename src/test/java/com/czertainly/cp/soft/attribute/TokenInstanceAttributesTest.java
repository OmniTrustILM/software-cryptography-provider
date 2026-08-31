package com.czertainly.cp.soft.attribute;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.RequestAttributeV2;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.attribute.common.callback.AttributeCallback;
import com.czertainly.api.model.common.attribute.common.callback.AttributeCallbackMapping;
import com.czertainly.api.model.common.attribute.common.callback.AttributeValueTarget;
import com.czertainly.api.model.common.attribute.common.constraint.RegexpAttributeConstraint;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.DataAttributeV2;
import com.czertainly.api.model.common.attribute.v2.GroupAttributeV2;
import com.czertainly.api.model.common.attribute.v2.InfoAttributeV2;
import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.core.util.AttributeDefinitionUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

import static com.czertainly.cp.soft.attribute.AttributeAssert.assertDataAttribute;
import static com.czertainly.cp.soft.attribute.AttributeAssert.assertSelectionList;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenInstanceAttributesTest {

    @Test
    void createTokenActionCarriesTheActionAsItsOwnContent() {
        DataAttributeV2 attribute = assertDataAttribute(
                TokenInstanceAttributes.buildDataCreateTokenAction("new"),
                TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION_UUID,
                TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION,
                AttributeContentType.STRING,
                TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION_LABEL);

        // Carries the action the platform is to perform, and is hidden from the operator.
        assertFalse(attribute.getProperties().isVisible(), "the action attribute must stay hidden");
        assertEquals(1, attribute.getContent().size());
        assertEquals("new", attribute.getContent().get(0).getReference());
        assertEquals("new", attribute.getContent().get(0).getData());
    }

    @Test
    void tokenCodeIsCarriedAsASecret() {
        DataAttributeV2 attribute = assertDataAttribute(
                TokenInstanceAttributes.buildDataTokenCode(),
                TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE_UUID,
                TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE,
                AttributeContentType.SECRET,
                TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE_LABEL);

        // The keystore password reaches the connector through this attribute. A content type
        // other than SECRET would have the platform store and display it in the clear.
        assertTrue(attribute.getProperties().isRequired());
        assertNull(attribute.getContent(), "no content may be baked into the activation code attribute");
    }

    @Test
    void newTokenNameRestrictsTheAcceptedForm() {
        DataAttributeV2 attribute = assertDataAttribute(
                TokenInstanceAttributes.buildDataNewTokenName(),
                TokenInstanceAttributes.ATTRIBUTE_DATA_NEW_TOKEN_NAME_UUID,
                TokenInstanceAttributes.ATTRIBUTE_DATA_NEW_TOKEN_NAME,
                AttributeContentType.STRING,
                TokenInstanceAttributes.ATTRIBUTE_DATA_NEW_TOKEN_NAME_LABEL);

        assertEquals(1, attribute.getConstraints().size());
        RegexpAttributeConstraint constraint =
                assertInstanceOf(RegexpAttributeConstraint.class, attribute.getConstraints().get(0));
        assertEquals("^[a-zA-Z](?:_?[a-zA-Z0-9]+)*$", constraint.getData());
        assertEquals("Invalid name for the Token", constraint.getErrorMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"Token", "Token1", "a_b", "Aa_aa", "A1_b2_c3"})
    void tokenNamePatternAcceptsValidNames(String name) {
        assertTrue(tokenNamePattern().matcher(name).matches(), name + " should be accepted");
    }

    @ParameterizedTest
    @ValueSource(strings = {"1Token", "_token", "token_", "to__ken", "to ken", "token-1", ""})
    void tokenNamePatternRejectsInvalidNames(String name) {
        assertFalse(tokenNamePattern().matcher(name).matches(), name + " should be rejected");
    }

    private static Pattern tokenNamePattern() {
        DataAttributeV2 attribute = (DataAttributeV2) TokenInstanceAttributes.buildDataNewTokenName();
        RegexpAttributeConstraint constraint =
                (RegexpAttributeConstraint) attribute.getConstraints().get(0);
        return Pattern.compile(constraint.getData());
    }

    @Test
    void tokenNameIsValidatedAgainstTheDefinition() {
        List<BaseAttribute> definition = List.of(TokenInstanceAttributes.buildDataNewTokenName());

        RequestAttributeV2 requested = new RequestAttributeV2();
        requested.setName(definition.get(0).getName());
        requested.setUuid(UUID.fromString(definition.get(0).getUuid()));
        StringAttributeContentV2 content = new StringAttributeContentV2();
        content.setReference("reference");
        content.setData("Aa_aa");
        requested.setContent(List.of(content));

        List<RequestAttribute> request = List.of(requested);
        assertDoesNotThrow(() -> AttributeDefinitionUtils.validateAttributes(definition, request));
    }

    @Test
    void optionsOfferCreatingOrSelectingAToken() {
        DataAttributeV2 attribute = assertDataAttribute(
                TokenInstanceAttributes.buildOptions(),
                TokenInstanceAttributes.ATTRIBUTE_DATA_OPTIONS_UUID,
                TokenInstanceAttributes.ATTRIBUTE_DATA_OPTIONS,
                AttributeContentType.STRING,
                "Select the options to add Token");
        assertSelectionList(attribute, true);

        // The data of the selected option becomes the {option} path variable of the callback.
        assertEquals(List.of("new", "existing"),
                attribute.getContent().stream().map(BaseAttributeContentV2::getData).toList());
        assertEquals(List.of("Create new Token", "Select existing Token"),
                attribute.getContent().stream().map(BaseAttributeContentV2::getReference).toList());
    }

    @Test
    void groupCallsBackWithTheSelectedOption() {
        GroupAttributeV2 group = assertInstanceOf(GroupAttributeV2.class,
                TokenInstanceAttributes.buildGroupBasedOnSelect());
        assertEquals(TokenInstanceAttributes.ATTRIBUTE_GROUP_LOAD_TOKEN_UUID, group.getUuid());
        assertEquals(TokenInstanceAttributes.ATTRIBUTE_GROUP_LOAD_TOKEN, group.getName());
        assertEquals(AttributeType.GROUP, group.getType());

        AttributeCallback callback = group.getAttributeCallback();
        assertNotNull(callback);
        assertEquals("/v1/cryptographyProvider/callbacks/token/{option}/attributes", callback.getCallbackContext());
        assertEquals("GET", callback.getCallbackMethod());

        assertEquals(1, callback.getMappings().size());
        AttributeCallbackMapping mapping = callback.getMappings().iterator().next();
        assertEquals(TokenInstanceAttributes.ATTRIBUTE_DATA_OPTIONS + ".data", mapping.getFrom());
        assertEquals("option", mapping.getTo());
        assertEquals(AttributeValueTarget.PATH_VARIABLE, mapping.getTargets().iterator().next());
    }

    @Test
    void informationalAttributesAreRenderedAsText() {
        InfoAttributeV2 initial = assertInstanceOf(InfoAttributeV2.class, TokenInstanceAttributes.buildInitialInfo());
        assertEquals(TokenInstanceAttributes.ATTRIBUTE_INFO_INITIAL_UUID, initial.getUuid());
        assertEquals(AttributeType.INFO, initial.getType());
        assertEquals(AttributeContentType.TEXT, initial.getContentType());
        assertFalse(initial.getContent().isEmpty());

        InfoAttributeV2 newToken = assertInstanceOf(InfoAttributeV2.class, TokenInstanceAttributes.buildInfoNewToken());
        assertEquals(TokenInstanceAttributes.ATTRIBUTE_INFO_NEW_TOKEN_UUID, newToken.getUuid());
        assertEquals(AttributeContentType.TEXT, newToken.getContentType());
        assertFalse(newToken.getContent().isEmpty());
    }

    @Test
    void selectExistingTokenOffersTheSuppliedTokens() {
        List<BaseAttributeContentV2<?>> tokens = List.of(
                new StringAttributeContentV2("first", "11111111-1111-1111-1111-111111111111"),
                new StringAttributeContentV2("second", "22222222-2222-2222-2222-222222222222"));

        DataAttributeV2 attribute = assertDataAttribute(
                TokenInstanceAttributes.buildDataSelectExistingToken(tokens),
                TokenInstanceAttributes.ATTRIBUTE_DATA_SELECT_EXISTING_TOKEN_UUID,
                TokenInstanceAttributes.ATTRIBUTE_DATA_SELECT_EXISTING_TOKEN,
                AttributeContentType.STRING,
                TokenInstanceAttributes.ATTRIBUTE_DATA_SELECT_EXISTING_TOKEN_DESCRIPTION);
        assertSelectionList(attribute, true);
        assertEquals(2, attribute.getContent().size());
        assertEquals("first", attribute.getContent().get(0).getReference());
    }

    @Test
    void selectExistingTokenToleratesAnEmptyTokenList() {
        DataAttributeV2 attribute =
                (DataAttributeV2) TokenInstanceAttributes.buildDataSelectExistingToken(List.of());
        assertNotNull(attribute.getContent());
        assertTrue(attribute.getContent().isEmpty());
    }

    @Test
    void newTokenSetAsksForNameAndActivationCode() {
        List<BaseAttribute> attributes = TokenInstanceAttributes.getNewTokenAttributes();
        assertEquals(List.of(
                TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION,
                TokenInstanceAttributes.ATTRIBUTE_INFO_NEW_TOKEN,
                TokenInstanceAttributes.ATTRIBUTE_DATA_NEW_TOKEN_NAME,
                TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE),
                attributes.stream().map(BaseAttribute::getName).toList());
    }

    @Test
    void newTokenSetWithoutInfoDropsOnlyTheInformationalAttribute() {
        List<BaseAttribute> attributes = TokenInstanceAttributes.getNewTokenAttributesWithoutInfo();
        assertEquals(List.of(
                TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION,
                TokenInstanceAttributes.ATTRIBUTE_DATA_NEW_TOKEN_NAME,
                TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE),
                attributes.stream().map(BaseAttribute::getName).toList());
    }

    @Test
    void existingTokenSetSelectsATokenAndAsksForItsCode() {
        List<BaseAttributeContentV2<?>> tokens = List.of(new StringAttributeContentV2("only", "only"));
        List<BaseAttribute> attributes = TokenInstanceAttributes.getExistingTokenAttributes(tokens);
        assertEquals(List.of(
                TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION,
                TokenInstanceAttributes.ATTRIBUTE_DATA_SELECT_EXISTING_TOKEN,
                TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE),
                attributes.stream().map(BaseAttribute::getName).toList());

        DataAttributeV2 action = (DataAttributeV2) attributes.get(0);
        assertEquals("existing", action.getContent().get(0).getData());
    }
}
