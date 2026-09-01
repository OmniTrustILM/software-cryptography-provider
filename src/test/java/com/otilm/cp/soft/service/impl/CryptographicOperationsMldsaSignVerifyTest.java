package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.otilm.cp.soft.attribute.MLDSAKeyAttributes;
import com.otilm.cp.soft.collection.MLDSASecurityCategory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

class CryptographicOperationsMldsaSignVerifyTest extends AbstractCryptographicOperationsTest {

    static Stream<Arguments> parameters() {
        return Stream.of(
                Arguments.of(MLDSASecurityCategory.MLDSA_44, false),
                Arguments.of(MLDSASecurityCategory.MLDSA_65, false),
                Arguments.of(MLDSASecurityCategory.MLDSA_87, false),
                Arguments.of(MLDSASecurityCategory.MLDSA_44, true),
                Arguments.of(MLDSASecurityCategory.MLDSA_65, true),
                Arguments.of(MLDSASecurityCategory.MLDSA_87, true)
        );
    }

    @ParameterizedTest(name = "{0} prehash={1}")
    @MethodSource("parameters")
    void testSignVerifyMldsa(MLDSASecurityCategory level, boolean prehash) throws NotFoundException {
        // Create key pair
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        createKeyRequestDto.setCreateKeyAttributes(buildMldsaCreateKeyAttributes("test-mldsa-" + level.name(), level, prehash));

        KeyPairDataResponseDto keyPair = keyManagementService.createKeyPair(tokenInstance.getUuid(), createKeyRequestDto);

        Assertions.assertEquals(KeyAlgorithm.MLDSA, keyPair.getPrivateKeyData().getKeyData().getAlgorithm());
        Assertions.assertEquals(KeyAlgorithm.MLDSA, keyPair.getPublicKeyData().getKeyData().getAlgorithm());

        UUID privateKeyUuid = UUID.fromString(keyPair.getPrivateKeyData().getUuid());
        UUID publicKeyUuid = UUID.fromString(keyPair.getPublicKeyData().getUuid());

        // Sign
        byte[] plaintext = "Hello, ILM!".getBytes();
        SignDataRequestDto signRequest = new SignDataRequestDto();
        signRequest.setSignatureAttributes(List.of());
        signRequest.setData(List.of(new SignatureRequestData(plaintext, "item-1")));

        SignDataResponseDto signResponse = cryptographicOperationsService.signData(
                tokenInstance.getUuid(), privateKeyUuid, signRequest);

        Assertions.assertNotNull(signResponse.getSignatures());
        Assertions.assertEquals(1, signResponse.getSignatures().size());
        byte[] signatureBytes = signResponse.getSignatures().get(0).getData();
        Assertions.assertNotNull(signatureBytes);
        Assertions.assertTrue(signatureBytes.length > 0);
        Assertions.assertNull(signResponse.getSignatures().get(0).getDetails());

        // Verify
        VerifyDataRequestDto verifyRequest = new VerifyDataRequestDto();
        verifyRequest.setSignatureAttributes(List.of());
        verifyRequest.setData(List.of(new SignatureRequestData(plaintext, "item-1")));
        verifyRequest.setSignatures(List.of(new SignatureRequestData(signatureBytes, "item-1")));

        VerifyDataResponseDto verifyResponse = cryptographicOperationsService.verifyData(
                tokenInstance.getUuid(), publicKeyUuid, verifyRequest);

        Assertions.assertNotNull(verifyResponse.getVerifications());
        Assertions.assertEquals(1, verifyResponse.getVerifications().size());
        Assertions.assertTrue(verifyResponse.getVerifications().get(0).isResult());
    }

    private List<RequestAttribute> buildMldsaCreateKeyAttributes(String alias, MLDSASecurityCategory level, boolean prehash) {
        List<RequestAttribute> attributes = new ArrayList<>();
        attributes.add(buildAliasAttribute(alias));
        attributes.add(buildAlgorithmAttribute(KeyAlgorithm.MLDSA));

        RequestAttributeV2 levelAttr = new RequestAttributeV2();
        levelAttr.setName(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_LEVEL);
        levelAttr.setContentType(AttributeContentType.INTEGER);
        levelAttr.setContent(List.of(new IntegerAttributeContentV2(level.name(), level.getNistSecurityCategory())));
        attributes.add(levelAttr);

        RequestAttributeV2 prehashAttr = new RequestAttributeV2();
        prehashAttr.setName(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_PREHASH);
        prehashAttr.setContentType(AttributeContentType.BOOLEAN);
        prehashAttr.setContent(List.of(new BooleanAttributeContentV2(prehash)));
        attributes.add(prehashAttr);

        return attributes;
    }
}
