package com.otilm.cp.soft.testsupport;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyExportableAttribute;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Key creation requests as the V2 interfaces carry them, for the tests that need one.
 */
public final class KeyRequestFixtures {

    private KeyRequestFixtures() {
    }

    /** A request creating a 2048-bit RSA key pair under a token of the given name. */
    public static CreateKeyRequestV2Dto rsaKeyPair(String tokenName, String alias) {
        CreateKeyRequestV2Dto request = new CreateKeyRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(tokenName));
        request.setTokenProfileAttributes(List.of());
        request.setKeyUsages(Set.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);
        request.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        request.setKeyCreationId(UUID.randomUUID().toString());
        request.setCreateKeyAttributes(rsaAttributes(alias));
        return request;
    }

    /** The reserved attribute stating whether a created key may ever leave the token. */
    public static RequestAttribute exportableIntent(boolean exportable) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(KeyExportableAttribute.NAME);
        attribute.setContent(List.of(new BooleanAttributeContentV2(exportable)));
        return attribute;
    }

    private static List<RequestAttribute> rsaAttributes(String alias) {
        List<RequestAttribute> attributes = new ArrayList<>();
        attributes.add(TokenContextFixtures.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS, alias));
        attributes.add(TokenContextFixtures.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, "RSA"));

        RequestAttributeV2 keySize = new RequestAttributeV2();
        keySize.setName(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE);
        keySize.setContent(List.of(new IntegerAttributeContentV2(2048)));
        attributes.add(keySize);

        return attributes;
    }
}
