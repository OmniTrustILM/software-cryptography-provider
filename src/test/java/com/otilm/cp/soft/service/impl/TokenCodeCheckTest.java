package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.cp.soft.exception.TokenInstanceException;
import com.otilm.cp.soft.model.TokenContext;
import com.otilm.cp.soft.service.TokenContextService;
import com.otilm.cp.soft.service.TokenInstanceService;
import com.otilm.cp.soft.testsupport.TokenContextFixtures;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The code a V2 context carries has to open the token, and it is checked on every request.
 *
 * <p>
 * Opening a keystore means deriving a key from the code over the whole of its content, which is too much to do on every
 * request; the code stored beside the keystore is known to open it, so comparing the two settles it. A token with no
 * code stored has none to compare against, which is how a token deactivated through the V1 interfaces is checked, and
 * these hold both ways of checking to the same answer.
 * </p>
 */
@SpringBootTest
class TokenCodeCheckTest {

    private TokenContextService tokenContextService;

    private TokenInstanceService tokenInstanceService;

    @Autowired
    void setTokenContextService(TokenContextService tokenContextService) {
        this.tokenContextService = tokenContextService;
    }

    @Autowired
    void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @Test
    void acceptsTheCodeTheTokenWasMadeWith() {
        // given
        String name = TokenContextFixtures.uniqueName("v2-code-right");

        // when
        TokenContext resolved = tokenContextService.resolve(TokenContextFixtures.newToken(name));

        // then
        assertEquals(name, resolved.instance().getName());
    }

    @Test
    void refusesACodeThatIsNotTheTokensOwn() {
        // given
        String name = TokenContextFixtures.uniqueName("v2-code-wrong");
        tokenContextService.resolve(TokenContextFixtures.newToken(name));
        List<RequestAttribute> wrongCode = TokenContextFixtures.newToken(name, "87654321");

        // when
        // then
        assertThrows(TokenInstanceException.class, () -> tokenContextService.resolve(wrongCode));
    }

    /** A token the V1 interfaces deactivated has no code stored, so the keystore itself is what answers. */
    @Test
    void checksATokenWithNoCodeStoredAgainstItsKeystore() throws NotFoundException {
        // given
        String name = TokenContextFixtures.uniqueName("v2-code-deactivated");
        UUID token = tokenContextService.resolve(TokenContextFixtures.newToken(name)).instance().getUuid();
        tokenInstanceService.deactivateTokenInstance(token);

        // when
        // then
        List<RequestAttribute> wrongCode = TokenContextFixtures.newToken(name, "87654321");
        assertThrows(TokenInstanceException.class, () -> tokenContextService.resolve(wrongCode));
        assertEquals(name, tokenContextService.resolve(TokenContextFixtures.newToken(name)).instance().getName(),
                "the right code has to bring a deactivated token back into use");
    }
}
