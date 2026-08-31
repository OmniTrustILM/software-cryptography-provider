package com.czertainly.cp.soft.service.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.RequestAttributeV2;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto;
import com.czertainly.cp.soft.attribute.KeyAttributes;
import com.czertainly.cp.soft.attribute.TokenInstanceActivationAttributes;
import com.czertainly.cp.soft.attribute.TokenInstanceAttributes;
import com.czertainly.cp.soft.service.TokenInstanceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AttributeServiceImplTest {

    private static final String KIND = "SOFT";
    private static final String TOKEN_UUID = "11111111-2222-3333-4444-555555555555";

    private TokenInstanceService tokenInstanceService;
    private AttributeServiceImpl service;

    @BeforeEach
    void setUp() {
        tokenInstanceService = mock(TokenInstanceService.class);
        service = new AttributeServiceImpl();
        service.setTokenInstanceService(tokenInstanceService);
    }

    private static List<String> names(List<BaseAttribute> attributes) {
        return attributes.stream().map(BaseAttribute::getName).toList();
    }

    @Test
    void withoutAnyTokenTheOperatorIsAskedToCreateOne() {
        when(tokenInstanceService.listTokenInstances()).thenReturn(null);

        assertEquals(names(TokenInstanceAttributes.getNewTokenAttributes()),
                names(service.getAttributes(KIND)));
    }

    @Test
    void withTokensAvailableTheOperatorChoosesBetweenNewAndExisting() {
        when(tokenInstanceService.listTokenInstances()).thenReturn(List.of(new TokenInstanceDto()));

        assertEquals(List.of(
                        TokenInstanceAttributes.ATTRIBUTE_INFO_INITIAL,
                        TokenInstanceAttributes.ATTRIBUTE_DATA_OPTIONS,
                        TokenInstanceAttributes.ATTRIBUTE_GROUP_LOAD_TOKEN),
                names(service.getAttributes(KIND)));
    }

    @Test
    void anEmptyTokenListStillOffersTheChoice() {
        // Only a null list means "no tokens at all"; an empty list is still a list.
        when(tokenInstanceService.listTokenInstances()).thenReturn(List.of());

        assertEquals(3, service.getAttributes(KIND).size());
    }

    @Test
    void activationAsksOnlyForTheActivationCode() {
        assertEquals(List.of(TokenInstanceActivationAttributes.ATTRIBUTE_DATA_ACTIVATION_CODE),
                names(service.getTokenInstanceActivationAttributes(TOKEN_UUID)));
    }

    @Test
    void createKeyAttributesRequireAnExistingToken() throws NotFoundException {
        when(tokenInstanceService.getTokenInstance(any(UUID.class))).thenReturn(null);

        assertEquals(List.of(
                        KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS,
                        KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM,
                        KeyAttributes.ATTRIBUTE_GROUP_KEY_SPEC),
                names(service.getCreateKeyAttributes(TOKEN_UUID)));

        verify(tokenInstanceService).getTokenInstance(UUID.fromString(TOKEN_UUID));
    }

    @Test
    void createKeyAttributesPropagateAnUnknownToken() throws NotFoundException {
        when(tokenInstanceService.getTokenInstance(any(UUID.class)))
                .thenThrow(new NotFoundException("token", TOKEN_UUID));

        assertThrows(NotFoundException.class, () -> service.getCreateKeyAttributes(TOKEN_UUID));
    }

    @Test
    void nullAttributesFailValidationRatherThanThrowing() throws NotFoundException {
        assertFalse(service.validateAttributes(KIND, null));
        assertFalse(service.validateTokenInstanceActivationAttributes(TOKEN_UUID, null));
        assertFalse(service.validateCreateKeyAttributes(TOKEN_UUID, null));
    }

    @Test
    void activationCodeIsValidatedAgainstItsDefinition() {
        List<RequestAttribute> request = List.of(
                requestFor(TokenInstanceActivationAttributes.buildDataTokenActivationCode(), "secret"));

        assertTrue(service.validateTokenInstanceActivationAttributes(TOKEN_UUID, request));
    }

    @Test
    void tokenOptionsAreValidatedAgainstTheirDefinition() {
        when(tokenInstanceService.listTokenInstances()).thenReturn(List.of(new TokenInstanceDto()));

        List<RequestAttribute> request = List.of(
                requestFor(TokenInstanceAttributes.buildOptions(), "new"));

        assertTrue(service.validateAttributes(KIND, request));
    }

    private static RequestAttribute requestFor(BaseAttribute definition, String value) {
        RequestAttributeV2 requested = new RequestAttributeV2();
        requested.setName(definition.getName());
        requested.setUuid(UUID.fromString(definition.getUuid()));
        requested.setContent(List.of(new StringAttributeContentV2(value, value)));
        return requested;
    }
}
