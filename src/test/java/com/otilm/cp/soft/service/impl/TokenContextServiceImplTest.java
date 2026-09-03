package com.otilm.cp.soft.service.impl;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.cp.soft.attribute.TokenInstanceAttributes;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.exception.TokenInstanceException;
import com.otilm.cp.soft.model.TokenContext;
import com.otilm.cp.soft.service.TokenContextService;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The V2 interfaces carry the token as attributes on every request and have no operation that creates one, so a token
 * comes into existence the first time a context naming a new one is used. Resolution is what turns those attributes
 * into the keystore the rest of the provider works with.
 */
@SpringBootTest
class TokenContextServiceImplTest {

    private static final String CODE = "00000000";

    private TokenContextService tokenContextService;

    @Autowired
    void setTokenContextService(TokenContextService tokenContextService) {
        this.tokenContextService = tokenContextService;
    }

    @Test
    void createsTheTokenTheFirstTimeAContextNamesANewOne() {
        // given
        String name = "v2-first-use-" + UUID.randomUUID();

        // when
        TokenContext context = tokenContextService.resolve(TokenContextFixtures.newToken(name, CODE));

        // then
        assertNotNull(context.instance().getUuid());
        assertEquals(name, context.instance().getName());
        assertEquals(CODE, context.code());
        assertNotNull(context.instance().getData(), "a resolved token must have a keystore behind it");
    }

    /** Every later request carries the same attributes, and must land on the token the first one created. */
    @Test
    void resolvesToTheSameTokenOnEveryLaterUse() {
        // given
        String name = "v2-repeat-" + UUID.randomUUID();
        TokenContext first = tokenContextService.resolve(TokenContextFixtures.newToken(name, CODE));

        // when
        TokenContext second = tokenContextService.resolve(TokenContextFixtures.newToken(name, CODE));

        // then
        assertEquals(first.instance().getUuid(), second.instance().getUuid());
    }

    @Test
    void resolvesATokenTheContextSelectsByIdentity() {
        // given
        String name = "v2-selected-" + UUID.randomUUID();
        UUID existing = tokenContextService.resolve(TokenContextFixtures.newToken(name, CODE)).instance().getUuid();

        // when
        TokenContext context = tokenContextService.resolve(TokenContextFixtures.existingToken(existing, name, CODE));

        // then
        assertEquals(existing, context.instance().getUuid());
    }

    /** The code is what opens the keystore, so a context carrying the wrong one cannot be used for anything. */
    @Test
    void refusesAContextWhoseCodeDoesNotOpenTheToken() {
        // given
        String name = "v2-wrong-code-" + UUID.randomUUID();
        tokenContextService.resolve(TokenContextFixtures.newToken(name, CODE));

        // when
        List<RequestAttribute> wrongCode = TokenContextFixtures.newToken(name, "99999999");
        TokenInstanceException failure = assertThrows(TokenInstanceException.class,
                () -> tokenContextService.resolve(wrongCode));

        // then
        assertTrue(failure.getMessage().contains(name), failure.getMessage());
    }

    /**
     * A context selecting a token that is gone addresses something this connector does not hold, which the contract
     * answers as a missing object. Reporting it as an attribute problem would tell the caller to correct a context that
     * is in fact well formed.
     */
    @Test
    void reportsASelectedTokenThatDoesNotExistAsMissing() {
        // given
        UUID unknown = UUID.randomUUID();
        List<RequestAttribute> missing = TokenContextFixtures.existingToken(unknown, "gone", CODE);

        // when
        // then
        assertThrows(ResourceMissingException.class, () -> tokenContextService.resolve(missing));
    }

    @Test
    void refusesAContextThatNamesNoToken() {
        // given
        List<RequestAttribute> attributes = new ArrayList<>();
        attributes.add(TokenContextFixtures.string(TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION, "new"));
        attributes.add(TokenContextFixtures.secret(TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE, CODE));

        // when
        // then
        assertThrows(TokenInstanceException.class, () -> tokenContextService.resolve(attributes));
    }

    @Test
    void refusesAnActionItDoesNotKnow() {
        // given
        List<RequestAttribute> attributes = TokenContextFixtures.newToken("v2-unknown-action", CODE);
        attributes
                .set(0, TokenContextFixtures
                        .string(TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION, "borrow"));

        // when
        // then
        assertThrows(TokenInstanceException.class, () -> tokenContextService.resolve(attributes));
    }

}
