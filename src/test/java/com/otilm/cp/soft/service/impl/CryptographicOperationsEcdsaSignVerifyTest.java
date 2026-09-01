package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.otilm.cp.soft.attribute.EcdsaKeyAttributes;
import com.otilm.cp.soft.collection.EcdsaCurveName;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

class CryptographicOperationsEcdsaSignVerifyTest extends AbstractCryptographicOperationsTest {

    static Stream<Arguments> parameters() {
        return Stream.of(
                Arguments.of(EcdsaCurveName.secp256r1, DigestAlgorithm.SHA_256),
                Arguments.of(EcdsaCurveName.secp256r1, DigestAlgorithm.SHA_384),
                Arguments.of(EcdsaCurveName.secp384r1, DigestAlgorithm.SHA_256),
                Arguments.of(EcdsaCurveName.secp384r1, DigestAlgorithm.SHA_384),
                Arguments.of(EcdsaCurveName.secp384r1, DigestAlgorithm.SHA_512),
                Arguments.of(EcdsaCurveName.secp521r1, DigestAlgorithm.SHA_384),
                Arguments.of(EcdsaCurveName.secp521r1, DigestAlgorithm.SHA_512)
        );
    }

    @ParameterizedTest(name = "{0} + {1}")
    @MethodSource("parameters")
    void testSignVerifyEcdsa(EcdsaCurveName curve, DigestAlgorithm digest) throws NotFoundException {
        // Create key pair
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        createKeyRequestDto.setCreateKeyAttributes(buildEcdsaCreateKeyAttributes("test-ecdsa-" + curve.getName(), curve));

        KeyPairDataResponseDto keyPair = keyManagementService.createKeyPair(tokenInstance.getUuid(), createKeyRequestDto);

        Assertions.assertEquals(KeyAlgorithm.ECDSA, keyPair.getPrivateKeyData().getKeyData().getAlgorithm());
        Assertions.assertEquals(KeyAlgorithm.ECDSA, keyPair.getPublicKeyData().getKeyData().getAlgorithm());

        UUID privateKeyUuid = UUID.fromString(keyPair.getPrivateKeyData().getUuid());
        UUID publicKeyUuid = UUID.fromString(keyPair.getPublicKeyData().getUuid());

        // Sign
        byte[] plaintext = "Hello, ILM!".getBytes();
        SignDataRequestDto signRequest = new SignDataRequestDto();
        signRequest.setSignatureAttributes(buildEcdsaSignatureAttributes(digest));
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
        verifyRequest.setSignatureAttributes(buildEcdsaSignatureAttributes(digest));
        verifyRequest.setData(List.of(new SignatureRequestData(plaintext, "item-1")));
        verifyRequest.setSignatures(List.of(new SignatureRequestData(signatureBytes, "item-1")));

        VerifyDataResponseDto verifyResponse = cryptographicOperationsService.verifyData(
                tokenInstance.getUuid(), publicKeyUuid, verifyRequest);

        Assertions.assertNotNull(verifyResponse.getVerifications());
        Assertions.assertEquals(1, verifyResponse.getVerifications().size());
        Assertions.assertTrue(verifyResponse.getVerifications().get(0).isResult());
    }

    private List<RequestAttribute> buildEcdsaCreateKeyAttributes(String alias, EcdsaCurveName curve) {
        List<RequestAttribute> attributes = new ArrayList<>();
        attributes.add(buildAliasAttribute(alias));
        attributes.add(buildAlgorithmAttribute(KeyAlgorithm.ECDSA));

        RequestAttributeV2 curveAttr = new RequestAttributeV2();
        curveAttr.setName(EcdsaKeyAttributes.ATTRIBUTE_DATA_ECDSA_CURVE);
        curveAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 curveContent = new StringAttributeContentV2();
        curveContent.setReference(curve.getName());
        curveContent.setData(curve.getName());
        curveAttr.setContent(List.of(curveContent));
        attributes.add(curveAttr);

        return attributes;
    }

    private List<RequestAttribute> buildEcdsaSignatureAttributes(DigestAlgorithm digest) {
        List<RequestAttribute> attributes = new ArrayList<>();

        RequestAttributeV2 digestAttr = new RequestAttributeV2();
        digestAttr.setName(EcdsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST);
        digestAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 digestContent = new StringAttributeContentV2();
        digestContent.setReference(digest.getCode());
        digestContent.setData(digest.getCode());
        digestAttr.setContent(List.of(digestContent));
        attributes.add(digestAttr);

        return attributes;
    }
}
