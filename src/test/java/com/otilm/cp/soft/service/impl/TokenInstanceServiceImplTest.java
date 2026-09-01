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

    @Autowired
    void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
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
