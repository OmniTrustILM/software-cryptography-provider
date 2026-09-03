package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.token.TokenScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.token.TokenStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.token.TokenStatusV2;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.cp.soft.service.TokenContextService;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The V2 token operations answer about the token a request carries in its attributes. There is no operation that
 * creates, activates or removes one, so what is left is the schema a token is configured with and whether the token a
 * context addresses can be used.
 */
@SpringBootTest
class TokenV2ControllerImplTest {

    private TokenV2ControllerImpl controller;

    private TokenContextService tokenContextService;

    @Autowired
    void setController(TokenV2ControllerImpl controller) {
        this.controller = controller;
    }

    @Autowired
    void setTokenContextService(TokenContextService tokenContextService) {
        this.tokenContextService = tokenContextService;
    }

    @Test
    void publishesTheSchemaATokenIsConfiguredWith() {
        // given
        // when
        List<BaseAttribute> attributes = controller.listTokenAttributes();

        // then
        assertFalse(attributes.isEmpty(), "a token has to be configurable");
    }

    @Test
    void reportsATokenItCanOpenAsConnected() {
        // given
        String name = TokenContextFixtures.uniqueName("v2-status-connected");
        tokenContextService.resolve(TokenContextFixtures.newToken(name));

        // when
        TokenStatusResponseV2Dto status = controller.getTokenStatus(tokenRequest(TokenContextFixtures.newToken(name)));

        // then
        assertEquals(TokenStatusV2.CONNECTED, status.getStatus());
    }

    /** A token a context asks for but that has not been used yet is simply not there; it is created when it is used. */
    @Test
    void reportsATokenThatDoesNotExistYetAsDisconnected() {
        // given
        List<com.otilm.api.model.client.attribute.RequestAttribute> context = TokenContextFixtures
                .existingToken(UUID.randomUUID(), "never-created", TokenContextFixtures.CODE);

        // when
        TokenStatusResponseV2Dto status = controller.getTokenStatus(tokenRequest(context));

        // then
        assertEquals(TokenStatusV2.DISCONNECTED, status.getStatus());
        assertNotNull(status.getDetail());
    }

    /** Status reports rather than fails, and the detail it reports must never carry the code it was given. */
    @Test
    void reportsATokenItCannotOpenAsDisconnectedWithoutQuotingTheCode() {
        // given
        String name = TokenContextFixtures.uniqueName("v2-status-wrong-code");
        String wrongCode = "12345678";
        tokenContextService.resolve(TokenContextFixtures.newToken(name));

        // when
        TokenStatusResponseV2Dto status = controller
                .getTokenStatus(tokenRequest(TokenContextFixtures.newToken(name, wrongCode)));

        // then
        assertEquals(TokenStatusV2.DISCONNECTED, status.getStatus());
        assertFalse(String.valueOf(status.getDetail()).contains(wrongCode),
                () -> "the code leaked into " + status.getDetail());
    }

    @Test
    void publishesNoTokenProfileAttributes() {
        // given
        String name = TokenContextFixtures.uniqueName("v2-profile-attributes");

        // when
        List<BaseAttribute> attributes = controller
                .listTokenProfileAttributes(tokenRequest(TokenContextFixtures.newToken(name)));

        // then
        assertTrue(attributes.isEmpty(), "this provider needs nothing configured on a token profile");
    }

    @Test
    void publishesTheKeyUsagesItsKeysCanServe() {
        // given
        String name = TokenContextFixtures.uniqueName("v2-usages");

        // when
        List<KeyUsage> usages = controller.listTokenProfileKeyUsages(tokenRequest(TokenContextFixtures.newToken(name)));

        // then
        assertEquals(List.of(KeyUsage.SIGN, KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.DECRYPT), usages);
    }

    /** Secret keys are not implemented, so the provider must not offer to hold one. */
    @Test
    void offersKeyPairsOnly() {
        // given
        String name = TokenContextFixtures.uniqueName("v2-key-types");

        // when
        List<KeyRequestType> types = controller
                .listSupportedKeyRequestTypes(tokenProfileRequest(TokenContextFixtures.newToken(name)));

        // then
        assertEquals(List.of(KeyRequestType.KEY_PAIR), types);
    }

    private static TokenScopedRequestV2Dto tokenRequest(
            List<com.otilm.api.model.client.attribute.RequestAttribute> tokenAttributes) {
        TokenScopedRequestV2Dto request = new TokenScopedRequestV2Dto();
        request.setTokenAttributes(tokenAttributes);
        return request;
    }

    private static TokenProfileScopedRequestV2Dto tokenProfileRequest(
            List<com.otilm.api.model.client.attribute.RequestAttribute> tokenAttributes) {
        TokenProfileScopedRequestV2Dto request = new TokenProfileScopedRequestV2Dto();
        request.setTokenAttributes(tokenAttributes);
        request.setTokenProfileAttributes(List.of());
        request.setKeyUsages(Set.of(KeyUsage.SIGN));
        return request;
    }
}
