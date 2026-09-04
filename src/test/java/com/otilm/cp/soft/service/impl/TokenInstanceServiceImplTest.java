package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.connector.cryptography.token.TokenInstanceDto;
import com.otilm.api.model.connector.cryptography.token.TokenInstanceRequestDto;
import com.otilm.cp.soft.attribute.TokenInstanceAttributes;
import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.dao.repository.TokenInstanceRepository;
import com.otilm.cp.soft.exception.TokenInstanceException;
import com.otilm.cp.soft.service.TokenInstanceService;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class TokenInstanceServiceImplTest {

    private TokenInstanceService tokenInstanceService;

    private TokenInstanceRepository tokenInstanceRepository;

    @Autowired
    void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @Autowired
    void setTokenInstanceRepository(TokenInstanceRepository tokenInstanceRepository) {
        this.tokenInstanceRepository = tokenInstanceRepository;
    }

    /**
     * A request that carries no code cannot have a keystore made for it. The attribute is required, so a request
     * missing it is refused before it is validated only by mistake — but what answers it should say what is wrong with
     * the request rather than report a fault in this connector.
     */
    @Test
    void refusesACreateRequestThatCarriesNoCode() {
        // given
        TokenInstanceRequestDto request = createRequest("NoCodeToken", null);

        // when
        // then
        Assertions.assertThrows(TokenInstanceException.class, () -> tokenInstanceService.createTokenInstance(request));
    }

    /** A code stated as an empty secret is a code that is not there. */
    @Test
    void refusesACreateRequestWhoseCodeCarriesNoSecret() {
        // given
        TokenInstanceRequestDto request = createRequest("EmptyCodeToken", new SecretAttributeContentData(null));

        // when
        // then
        Assertions.assertThrows(TokenInstanceException.class, () -> tokenInstanceService.createTokenInstance(request));
    }

    /**
     * Addressing a token that already exists opens its keystore with the code the request carries, so a request that
     * carries none has nothing to open it with, exactly as when one is created.
     */
    @Test
    void refusesARequestForAnExistingTokenThatCarriesNoCode() throws AlreadyExistException {
        // given
        TokenInstanceDto existing = tokenInstanceService
                .createTokenInstance(createRequest("SelectedWithoutCode", new SecretAttributeContentData("00000000")));

        TokenInstanceRequestDto request = new TokenInstanceRequestDto();
        request.setKind("SOFT");
        request.setName(existing.getName());
        request
                .setAttributes(List
                        .of(stringAttribute(TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION, "existing"),
                                stringAttribute(TokenInstanceAttributes.ATTRIBUTE_DATA_SELECT_EXISTING_TOKEN,
                                        existing.getUuid())));

        // when
        // then
        Assertions.assertThrows(TokenInstanceException.class, () -> tokenInstanceService.createTokenInstance(request));
    }

    /**
     * Activation opens the stored keystore with the code the request carries, so a request that carries none has
     * nothing to open it with and is refused rather than reaching the keystore.
     */
    @Test
    void refusesAnActivationRequestThatCarriesNoCode() throws AlreadyExistException, NotFoundException {
        // given
        TokenInstanceDto token = tokenInstanceService
                .createTokenInstance(createRequest("ActivateWithoutCode", new SecretAttributeContentData("00000000")));
        UUID uuid = UUID.fromString(token.getUuid());
        clearTheStoredCode(uuid);

        // when
        // then
        Assertions
                .assertThrows(TokenInstanceException.class,
                        () -> tokenInstanceService.activateTokenInstance(uuid, List.of()));
    }

    /** Activation refuses a token that already carries a code, so the stored one is cleared to reach the read. */
    private void clearTheStoredCode(UUID uuid) throws NotFoundException {
        TokenInstance stored = tokenInstanceService.getTokenInstanceEntity(uuid);
        stored.setCode(null);
        tokenInstanceRepository.save(stored);
    }

    /** A create request for a new token, carrying the given code, or none at all when it is null. */
    private static TokenInstanceRequestDto createRequest(String name, SecretAttributeContentData code) {
        TokenInstanceRequestDto request = new TokenInstanceRequestDto();
        request.setKind("SOFT");
        request.setName(name);

        List<RequestAttribute> attributes = new ArrayList<>();
        attributes.add(stringAttribute(TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION, "new"));
        attributes.add(stringAttribute(TokenInstanceAttributes.ATTRIBUTE_DATA_NEW_TOKEN_NAME, name));
        if (code != null) {
            RequestAttributeV2 tokenCode = new RequestAttributeV2();
            tokenCode.setName(TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE);
            tokenCode.setContent(List.of(new SecretAttributeContentV2(name, code)));
            attributes.add(tokenCode);
        }

        request.setAttributes(attributes);
        return request;
    }

    private static RequestAttributeV2 stringAttribute(String name, String value) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(new StringAttributeContentV2(value, value)));
        return attribute;
    }

    @Test
    void testTokenDeleteOnRemoveFalse() throws AlreadyExistException, NotFoundException {
        // create dummy token instance
        TokenInstanceRequestDto request = new TokenInstanceRequestDto();
        request.setKind("SOFT");
        request.setName("DummyToken");

        List<RequestAttribute> attributes = new ArrayList<>();

        RequestAttributeV2 newTokenName = new RequestAttributeV2();
        newTokenName.setName(TokenInstanceAttributes.ATTRIBUTE_DATA_NEW_TOKEN_NAME);
        newTokenName.setContent(List.of(new StringAttributeContentV2("DummyToken")));
        attributes.add(newTokenName);

        RequestAttributeV2 createTokenAction = new RequestAttributeV2();
        createTokenAction.setName(TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION);
        createTokenAction.setContent(List.of(new StringAttributeContentV2("new", "new")));
        attributes.add(createTokenAction);

        RequestAttributeV2 options = new RequestAttributeV2();
        options.setName(TokenInstanceAttributes.ATTRIBUTE_DATA_OPTIONS);
        options.setContent(List.of(new StringAttributeContentV2("new", "Create new Token")));
        attributes.add(options);

        RequestAttributeV2 tokenCode = new RequestAttributeV2();
        tokenCode.setName(TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE);
        tokenCode
                .setContent(List
                        .of(new SecretAttributeContentV2("DummyToken", new SecretAttributeContentData("00000000"))));
        attributes.add(tokenCode);

        request.setAttributes(attributes);

        TokenInstanceDto token = tokenInstanceService.createTokenInstance(request);

        // delete token instance
        tokenInstanceService.removeTokenInstance(UUID.fromString(token.getUuid()));

        // check if token instance is still in database
        // it will throw NotFoundException if token instance is not in database
        Assertions
                .assertDoesNotThrow(
                        () -> tokenInstanceService.getTokenInstanceStatus(UUID.fromString(token.getUuid())));
    }

}
