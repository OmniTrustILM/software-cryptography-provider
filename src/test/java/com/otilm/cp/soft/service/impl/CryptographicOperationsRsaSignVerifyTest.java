package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class CryptographicOperationsRsaSignVerifyTest extends AbstractCryptographicOperationsTest {

    static Stream<Arguments> parameters() {
        // RSA-1024 + PSS + SHA_512 is excluded: PSS with SHA-512 and the default salt length
        // (sLen = hLen = 64 bytes) requires a modulus of at least
        // 8 * ceil((hLen + sLen + 2) / 8) = 8 * ceil(130 / 8) = 1040 bits.
        // A 1024-bit key is too small — BouncyCastle rejects it with
        // "key too small for specified hash and salt lengths".
        return Stream
                .of(Arguments.of(1024, RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_256),
                        Arguments.of(1024, RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_384),
                        Arguments.of(1024, RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_512),
                        Arguments.of(1024, RsaSignatureScheme.PSS, DigestAlgorithm.SHA_256),
                        Arguments.of(1024, RsaSignatureScheme.PSS, DigestAlgorithm.SHA_384),
                        Arguments.of(2048, RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_256),
                        Arguments.of(2048, RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_384),
                        Arguments.of(2048, RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_512),
                        Arguments.of(2048, RsaSignatureScheme.PSS, DigestAlgorithm.SHA_256),
                        Arguments.of(2048, RsaSignatureScheme.PSS, DigestAlgorithm.SHA_384),
                        Arguments.of(2048, RsaSignatureScheme.PSS, DigestAlgorithm.SHA_512),
                        Arguments.of(4096, RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_256),
                        Arguments.of(4096, RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_384),
                        Arguments.of(4096, RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_512),
                        Arguments.of(4096, RsaSignatureScheme.PSS, DigestAlgorithm.SHA_256),
                        Arguments.of(4096, RsaSignatureScheme.PSS, DigestAlgorithm.SHA_384),
                        Arguments.of(4096, RsaSignatureScheme.PSS, DigestAlgorithm.SHA_512));
    }

    @ParameterizedTest(name = "RSA-{0} {1} {2}")
    @MethodSource("parameters")
    void testSignVerifyRsa(int keySize, RsaSignatureScheme scheme, DigestAlgorithm digest) throws NotFoundException {
        // Create key pair
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        createKeyRequestDto.setCreateKeyAttributes(buildRsaCreateKeyAttributes("test-rsa-" + keySize, keySize));

        KeyPairDataResponseDto keyPair = keyManagementService
                .createKeyPair(tokenInstance.getUuid(), createKeyRequestDto);

        Assertions.assertEquals(KeyAlgorithm.RSA, keyPair.getPrivateKeyData().getKeyData().getAlgorithm());
        Assertions.assertEquals(KeyAlgorithm.RSA, keyPair.getPublicKeyData().getKeyData().getAlgorithm());

        UUID privateKeyUuid = UUID.fromString(keyPair.getPrivateKeyData().getUuid());
        UUID publicKeyUuid = UUID.fromString(keyPair.getPublicKeyData().getUuid());

        // Sign
        byte[] plaintext = "Hello, ILM!".getBytes();
        SignDataRequestDto signRequest = new SignDataRequestDto();
        signRequest.setSignatureAttributes(buildRsaSignatureAttributes(scheme, digest));
        signRequest.setData(List.of(new SignatureRequestData(plaintext, "item-1")));

        SignDataResponseDto signResponse = cryptographicOperationsService
                .signData(tokenInstance.getUuid(), privateKeyUuid, signRequest);

        Assertions.assertNotNull(signResponse.getSignatures());
        Assertions.assertEquals(1, signResponse.getSignatures().size());
        byte[] signatureBytes = signResponse.getSignatures().get(0).getData();
        Assertions.assertNotNull(signatureBytes);
        Assertions.assertTrue(signatureBytes.length > 0);
        Assertions.assertNull(signResponse.getSignatures().get(0).getDetails());

        // Verify
        VerifyDataRequestDto verifyRequest = new VerifyDataRequestDto();
        verifyRequest.setSignatureAttributes(buildRsaSignatureAttributes(scheme, digest));
        verifyRequest.setData(List.of(new SignatureRequestData(plaintext, "item-1")));
        verifyRequest.setSignatures(List.of(new SignatureRequestData(signatureBytes, "item-1")));

        VerifyDataResponseDto verifyResponse = cryptographicOperationsService
                .verifyData(tokenInstance.getUuid(), publicKeyUuid, verifyRequest);

        Assertions.assertNotNull(verifyResponse.getVerifications());
        Assertions.assertEquals(1, verifyResponse.getVerifications().size());
        Assertions.assertTrue(verifyResponse.getVerifications().get(0).isResult());
    }

    private List<RequestAttribute> buildRsaCreateKeyAttributes(String alias, int keySize) {
        List<RequestAttribute> attributes = new ArrayList<>();
        attributes.add(buildAliasAttribute(alias));
        attributes.add(buildAlgorithmAttribute(KeyAlgorithm.RSA));

        RequestAttributeV2 rsaKeySize = new RequestAttributeV2();
        rsaKeySize.setName(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE);
        rsaKeySize.setContentType(AttributeContentType.INTEGER);
        rsaKeySize.setContent(List.of(new IntegerAttributeContentV2("RSA_" + keySize, keySize)));
        attributes.add(rsaKeySize);

        return attributes;
    }

    private List<RequestAttribute> buildRsaSignatureAttributes(RsaSignatureScheme scheme, DigestAlgorithm digest) {
        List<RequestAttribute> attributes = new ArrayList<>();

        RequestAttributeV2 schemeAttr = new RequestAttributeV2();
        schemeAttr.setName(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME);
        schemeAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 schemeContent = new StringAttributeContentV2();
        schemeContent.setReference(scheme.getCode());
        schemeContent.setData(scheme.getCode());
        schemeAttr.setContent(List.of(schemeContent));
        attributes.add(schemeAttr);

        RequestAttributeV2 digestAttr = new RequestAttributeV2();
        digestAttr.setName(RsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST);
        digestAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 digestContent = new StringAttributeContentV2();
        digestContent.setReference(digest.getCode());
        digestContent.setData(digest.getCode());
        digestAttr.setContent(List.of(digestContent));
        attributes.add(digestAttr);

        return attributes;
    }
}
