package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.otilm.cp.soft.attribute.SLHDSAKeyAttributes;
import com.otilm.cp.soft.collection.SLHDSAHash;
import com.otilm.cp.soft.collection.SLHDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASignatureMode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

class CryptographicOperationsSlhdsaSignVerifyTest extends AbstractCryptographicOperationsTest {

    static Stream<Arguments> parameters() {
        return Stream.of(
                // prehash = false: all hash/mode combinations across all categories
                Arguments.of(SLHDSASecurityCategory.CATEGORY_1, SLHDSAHash.SHA2,    SLHDSASignatureMode.FAST,  false),
                Arguments.of(SLHDSASecurityCategory.CATEGORY_1, SLHDSAHash.SHA2,    SLHDSASignatureMode.SMALL, false),
                Arguments.of(SLHDSASecurityCategory.CATEGORY_1, SLHDSAHash.SHAKE256, SLHDSASignatureMode.FAST,  false),
                Arguments.of(SLHDSASecurityCategory.CATEGORY_1, SLHDSAHash.SHAKE256, SLHDSASignatureMode.SMALL, false),
                Arguments.of(SLHDSASecurityCategory.CATEGORY_3, SLHDSAHash.SHA2,    SLHDSASignatureMode.FAST,  false),
                Arguments.of(SLHDSASecurityCategory.CATEGORY_3, SLHDSAHash.SHA2,    SLHDSASignatureMode.SMALL, false),
                Arguments.of(SLHDSASecurityCategory.CATEGORY_3, SLHDSAHash.SHAKE256, SLHDSASignatureMode.FAST,  false),
                Arguments.of(SLHDSASecurityCategory.CATEGORY_3, SLHDSAHash.SHAKE256, SLHDSASignatureMode.SMALL, false),
                Arguments.of(SLHDSASecurityCategory.CATEGORY_5, SLHDSAHash.SHA2,    SLHDSASignatureMode.FAST,  false),
                Arguments.of(SLHDSASecurityCategory.CATEGORY_5, SLHDSAHash.SHA2,    SLHDSASignatureMode.SMALL, false),
                Arguments.of(SLHDSASecurityCategory.CATEGORY_5, SLHDSAHash.SHAKE256, SLHDSASignatureMode.FAST,  false),
                Arguments.of(SLHDSASecurityCategory.CATEGORY_5, SLHDSAHash.SHAKE256, SLHDSASignatureMode.SMALL, false),
                // prehash = true: representative hash/mode per category
                Arguments.of(SLHDSASecurityCategory.CATEGORY_1, SLHDSAHash.SHA2,    SLHDSASignatureMode.FAST,  true),
                Arguments.of(SLHDSASecurityCategory.CATEGORY_3, SLHDSAHash.SHA2,    SLHDSASignatureMode.FAST,  true),
                Arguments.of(SLHDSASecurityCategory.CATEGORY_5, SLHDSAHash.SHA2,    SLHDSASignatureMode.FAST,  true)
        );
    }

    @ParameterizedTest(name = "{0} {1} {2} prehash={3}")
    @MethodSource("parameters")
    void testSignVerifySlhDsa(SLHDSASecurityCategory category, SLHDSAHash hash,
                              SLHDSASignatureMode mode, boolean prehash) throws NotFoundException {
        // Create key pair
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        createKeyRequestDto.setCreateKeyAttributes(
                buildSlhDsaCreateKeyAttributes("test-slhdsa-" + category.name(), category, hash, mode, prehash));

        KeyPairDataResponseDto keyPair = keyManagementService.createKeyPair(tokenInstance.getUuid(), createKeyRequestDto);

        Assertions.assertEquals(KeyAlgorithm.SLHDSA, keyPair.getPrivateKeyData().getKeyData().getAlgorithm());
        Assertions.assertEquals(KeyAlgorithm.SLHDSA, keyPair.getPublicKeyData().getKeyData().getAlgorithm());

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

    private List<RequestAttribute> buildSlhDsaCreateKeyAttributes(
            String alias,
            SLHDSASecurityCategory category,
            SLHDSAHash hash,
            SLHDSASignatureMode mode,
            boolean prehash) {
        List<RequestAttribute> attributes = new ArrayList<>();
        attributes.add(buildAliasAttribute(alias));
        attributes.add(buildAlgorithmAttribute(KeyAlgorithm.SLHDSA));

        RequestAttributeV2 categoryAttr = new RequestAttributeV2();
        categoryAttr.setName(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY);
        categoryAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 categoryContent = new StringAttributeContentV2();
        categoryContent.setReference(category.name());
        categoryContent.setData(category.getNistSecurityCategory());
        categoryAttr.setContent(List.of(categoryContent));
        attributes.add(categoryAttr);

        RequestAttributeV2 hashAttr = new RequestAttributeV2();
        hashAttr.setName(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_HASH);
        hashAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 hashContent = new StringAttributeContentV2();
        hashContent.setReference(hash.name());
        hashContent.setData(hash.getHashName());
        hashAttr.setContent(List.of(hashContent));
        attributes.add(hashAttr);

        RequestAttributeV2 modeAttr = new RequestAttributeV2();
        modeAttr.setName(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE);
        modeAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 modeContent = new StringAttributeContentV2();
        modeContent.setReference(mode.name());
        modeContent.setData(mode.name());
        modeAttr.setContent(List.of(modeContent));
        attributes.add(modeAttr);

        RequestAttributeV2 prehashAttr = new RequestAttributeV2();
        prehashAttr.setName(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_PREHASH);
        prehashAttr.setContentType(AttributeContentType.BOOLEAN);
        prehashAttr.setContent(List.of(new BooleanAttributeContentV2(prehash)));
        attributes.add(prehashAttr);

        return attributes;
    }
}
