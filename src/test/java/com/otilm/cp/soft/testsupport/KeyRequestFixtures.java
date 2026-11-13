package com.otilm.cp.soft.testsupport;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyExportableAttribute;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.attribute.MLDSAKeyAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Key creation requests as the V2 interfaces carry them, for the tests that need one.
 */
public final class KeyRequestFixtures {

    private KeyRequestFixtures() {
    }

    /** A request creating a 2048-bit RSA key pair under a token of the given name. */
    public static CreateKeyRequestV2Dto rsaKeyPair(String tokenName, String alias) {
        return keyPair(tokenName, rsaAttributes(alias));
    }

    /** A request creating an ML-DSA-65 key pair that signs the message itself, under a token of the given name. */
    public static CreateKeyRequestV2Dto mldsaKeyPair(String tokenName, String alias) {
        return keyPair(tokenName, mldsaAttributes(alias));
    }

    private static CreateKeyRequestV2Dto keyPair(String tokenName, List<RequestAttribute> keyAttributes) {
        CreateKeyRequestV2Dto request = new CreateKeyRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(tokenName));
        request.setTokenProfileAttributes(List.of());
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);
        request.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        request.setKeyCreationId(UUID.randomUUID().toString());
        request.setCreateKeyAttributes(keyAttributes);
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
        attributes.add(TokenContextFixtures.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS_V2, alias));
        attributes.add(TokenContextFixtures.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, "RSA"));

        RequestAttributeV2 keySize = new RequestAttributeV2();
        keySize.setName(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE);
        keySize.setContent(List.of(new IntegerAttributeContentV2(2048)));
        attributes.add(keySize);

        return attributes;
    }

    private static List<RequestAttribute> mldsaAttributes(String alias) {
        RequestAttributeV2 level = new RequestAttributeV2();
        level.setName(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_LEVEL);
        level.setContent(List.of(new IntegerAttributeContentV2("MLDSA_65", 3)));

        RequestAttributeV2 prehash = new RequestAttributeV2();
        prehash.setName(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_PREHASH);
        prehash.setContent(List.of(new BooleanAttributeContentV2(false)));

        return List
                .of(TokenContextFixtures.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS_V2, alias),
                        TokenContextFixtures
                                .string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, KeyAlgorithm.MLDSA.getCode()),
                        level, prehash);
    }
}
