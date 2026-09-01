package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaEncryptionScheme;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.EncryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.data.CipherRequestData;
import com.otilm.cp.soft.attribute.RsaCipherAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

class CryptographicOperationsRsaEncryptDecryptTest extends AbstractCryptographicOperationsTest {

    private static final byte[] PLAINTEXT = "Hello, ILM!".getBytes();

    static Stream<Arguments> parameters() {
        // RSA-1024 + OAEP + SHA_512 is excluded: OAEP-SHA-512 has a fixed overhead of
        // 2 * hLen + 2 = 2 * 64 + 2 = 130 bytes, which already exceeds the 128-byte (1024-bit)
        // RSA block size, leaving no room for any plaintext.
        // BouncyCastle rejects this at encryption time with "too much data for RSA block".
        return Stream.of(
                // PKCS1_v1_5 — no digest, no MGF flag
                Arguments.of(1024, RsaEncryptionScheme.PKCS1_v1_5, null,                   false),
                Arguments.of(2048, RsaEncryptionScheme.PKCS1_v1_5, null,                   false),
                Arguments.of(4096, RsaEncryptionScheme.PKCS1_v1_5, null,                   false),
                // OAEP — 1024-bit key
                Arguments.of(1024, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_256, true),
                Arguments.of(1024, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_256, false),
                Arguments.of(1024, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_384, true),
                Arguments.of(1024, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_384, false),
                // OAEP — 2048-bit key
                Arguments.of(2048, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_256, true),
                Arguments.of(2048, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_256, false),
                Arguments.of(2048, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_384, true),
                Arguments.of(2048, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_384, false),
                Arguments.of(2048, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_512, true),
                Arguments.of(2048, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_512, false),
                // OAEP — 4096-bit key
                Arguments.of(4096, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_256, true),
                Arguments.of(4096, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_256, false),
                Arguments.of(4096, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_384, true),
                Arguments.of(4096, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_384, false),
                Arguments.of(4096, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_512, true),
                Arguments.of(4096, RsaEncryptionScheme.OAEP,       DigestAlgorithm.SHA_512, false)
        );
    }

    @ParameterizedTest(name = "RSA-{0} {1} {2} mgf={3}")
    @MethodSource("parameters")
    void testEncryptDecryptRsa(int keySize, RsaEncryptionScheme scheme,
                               DigestAlgorithm hash, boolean useMgf) throws NotFoundException {
        // Create key pair
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        createKeyRequestDto.setCreateKeyAttributes(buildRsaCreateKeyAttributes("test-rsa-" + keySize, keySize));

        KeyPairDataResponseDto keyPair = keyManagementService.createKeyPair(tokenInstance.getUuid(), createKeyRequestDto);

        UUID privateKeyUuid = UUID.fromString(keyPair.getPrivateKeyData().getUuid());
        UUID publicKeyUuid = UUID.fromString(keyPair.getPublicKeyData().getUuid());

        // Encrypt with public key
        CipherDataRequestDto encryptRequest = new CipherDataRequestDto();
        if (scheme == RsaEncryptionScheme.PKCS1_v1_5) {
            encryptRequest.setCipherAttributes(buildRsaPkcs1EncryptAttributes());
        } else {
            encryptRequest.setCipherAttributes(buildRsaOaepEncryptAttributes(hash, useMgf));
        }
        encryptRequest.setCipherData(List.of(new CipherRequestData(PLAINTEXT, "item-1")));

        EncryptDataResponseDto encryptResponse = cryptographicOperationsService.encryptData(
                tokenInstance.getUuid(), publicKeyUuid, encryptRequest);

        Assertions.assertNotNull(encryptResponse.getEncryptedData());
        Assertions.assertFalse(encryptResponse.getEncryptedData().isEmpty());
        byte[] encryptedBytes = encryptResponse.getEncryptedData().getFirst().getData();
        Assertions.assertFalse(java.util.Arrays.equals(encryptedBytes, PLAINTEXT),
                "Encrypted data should differ from plaintext");

        // Decrypt with private key
        CipherDataRequestDto decryptRequest = new CipherDataRequestDto();
        if (scheme == RsaEncryptionScheme.PKCS1_v1_5) {
            decryptRequest.setCipherAttributes(buildRsaPkcs1EncryptAttributes());
        } else {
            decryptRequest.setCipherAttributes(buildRsaOaepEncryptAttributes(hash, useMgf));
        }
        decryptRequest.setCipherData(List.of(new CipherRequestData(encryptedBytes, "item-1")));

        DecryptDataResponseDto decryptResponse = cryptographicOperationsService.decryptData(
                tokenInstance.getUuid(), privateKeyUuid, decryptRequest);

        Assertions.assertNotNull(decryptResponse.getDecryptedData());
        Assertions.assertFalse(decryptResponse.getDecryptedData().isEmpty());
        byte[] decryptedBytes = decryptResponse.getDecryptedData().getFirst().getData();
        Assertions.assertArrayEquals(PLAINTEXT, decryptedBytes,
                "Decrypted data should match original plaintext");
    }

    @Test
    void testEncryptRejectsPrivateKey() throws NotFoundException {
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        createKeyRequestDto.setCreateKeyAttributes(buildRsaCreateKeyAttributes("test-rsa-reject-enc", 2048));
        KeyPairDataResponseDto keyPair = keyManagementService.createKeyPair(tokenInstance.getUuid(), createKeyRequestDto);

        UUID privateKeyUuid = UUID.fromString(keyPair.getPrivateKeyData().getUuid());

        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherAttributes(buildRsaPkcs1EncryptAttributes());
        request.setCipherData(List.of(new CipherRequestData(PLAINTEXT, "item-1")));

        UUID tokenUuid = tokenInstance.getUuid();
        Assertions.assertThrows(CryptographicOperationException.class,
                () -> cryptographicOperationsService.encryptData(tokenUuid, privateKeyUuid, request),
                "encryptData with a private key should throw CryptographicOperationException");
    }

    @Test
    void testDecryptRejectsPublicKey() throws NotFoundException {
        CreateKeyRequestDto createKeyRequestDto = new CreateKeyRequestDto();
        createKeyRequestDto.setCreateKeyAttributes(buildRsaCreateKeyAttributes("test-rsa-reject-dec", 2048));
        KeyPairDataResponseDto keyPair = keyManagementService.createKeyPair(tokenInstance.getUuid(), createKeyRequestDto);

        UUID publicKeyUuid = UUID.fromString(keyPair.getPublicKeyData().getUuid());

        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherAttributes(buildRsaPkcs1EncryptAttributes());
        request.setCipherData(List.of(new CipherRequestData(PLAINTEXT, "item-1")));

        UUID tokenUuid = tokenInstance.getUuid();
        Assertions.assertThrows(CryptographicOperationException.class,
                () -> cryptographicOperationsService.decryptData(tokenUuid, publicKeyUuid, request),
                "decryptData with a public key should throw CryptographicOperationException");
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

    private List<RequestAttribute> buildRsaPkcs1EncryptAttributes() {
        List<RequestAttribute> attributes = new ArrayList<>();

        RequestAttributeV2 schemeAttr = new RequestAttributeV2();
        schemeAttr.setName(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME);
        schemeAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 schemeContent = new StringAttributeContentV2();
        schemeContent.setReference(RsaEncryptionScheme.PKCS1_v1_5.getCode());
        schemeContent.setData(RsaEncryptionScheme.PKCS1_v1_5.getCode());
        schemeAttr.setContent(List.of(schemeContent));
        attributes.add(schemeAttr);

        return attributes;
    }

    private List<RequestAttribute> buildRsaOaepEncryptAttributes(DigestAlgorithm hash, boolean useMgf) {
        List<RequestAttribute> attributes = new ArrayList<>();

        RequestAttributeV2 schemeAttr = new RequestAttributeV2();
        schemeAttr.setName(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME);
        schemeAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 schemeContent = new StringAttributeContentV2();
        schemeContent.setReference(RsaEncryptionScheme.OAEP.getCode());
        schemeContent.setData(RsaEncryptionScheme.OAEP.getCode());
        schemeAttr.setContent(List.of(schemeContent));
        attributes.add(schemeAttr);

        RequestAttributeV2 hashAttr = new RequestAttributeV2();
        hashAttr.setName(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME);
        hashAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 hashContent = new StringAttributeContentV2();
        hashContent.setReference(hash.getCode());
        hashContent.setData(hash.getCode());
        hashAttr.setContent(List.of(hashContent));
        attributes.add(hashAttr);

        RequestAttributeV2 mgfAttr = new RequestAttributeV2();
        mgfAttr.setName(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME);
        mgfAttr.setContentType(AttributeContentType.BOOLEAN);
        mgfAttr.setContent(List.of(new BooleanAttributeContentV2(useMgf)));
        attributes.add(mgfAttr);

        return attributes;
    }
}
