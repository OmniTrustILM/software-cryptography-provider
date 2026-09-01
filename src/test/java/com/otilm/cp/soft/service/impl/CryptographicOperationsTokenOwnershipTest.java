package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaEncryptionScheme;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.data.CipherRequestData;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.otilm.cp.soft.attribute.RsaCipherAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.util.KeyStoreUtil;
import jakarta.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Verifies that cryptographic operations reject requests where the token instance UUID in the path does not match the
 * token instance that owns the referenced key.
 */
@Transactional
class CryptographicOperationsTokenOwnershipTest extends AbstractCryptographicOperationsTest {

    private static final byte[] PLAINTEXT = "Hello, ILM!".getBytes();

    private TokenInstance otherTokenInstance;

    @BeforeEach
    void setUpOtherToken() {
        otherTokenInstance = new TokenInstance();
        otherTokenInstance.setCode(PASSWORD);
        otherTokenInstance.setData(KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD));
        tokenInstanceRepository.save(otherTokenInstance);
    }

    @Test
    void signData_withMismatchedTokenUuid_shouldThrowNotFoundException() throws NotFoundException {
        KeyPairDataResponseDto pair = keyManagementService
                .createKeyPair(tokenInstance.getUuid(), buildRsaCreateKeyRequest("own-sign"));
        UUID privateKeyUuid = UUID.fromString(pair.getPrivateKeyData().getUuid());

        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(buildRsaSignatureAttributes());
        request.setData(List.of(new SignatureRequestData(PLAINTEXT, "item-1")));

        UUID wrongTokenUuid = otherTokenInstance.getUuid();
        assertThrows(NotFoundException.class,
                () -> cryptographicOperationsService.signData(wrongTokenUuid, privateKeyUuid, request),
                "signData should reject a key that belongs to a different token instance");
    }

    @Test
    void verifyData_withMismatchedTokenUuid_shouldThrowNotFoundException() throws NotFoundException {
        KeyPairDataResponseDto pair = keyManagementService
                .createKeyPair(tokenInstance.getUuid(), buildRsaCreateKeyRequest("own-verify"));
        UUID publicKeyUuid = UUID.fromString(pair.getPublicKeyData().getUuid());

        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatureAttributes(buildRsaSignatureAttributes());
        request.setData(List.of(new SignatureRequestData(PLAINTEXT, "item-1")));
        request.setSignatures(List.of(new SignatureRequestData(new byte[256], "item-1")));

        UUID wrongTokenUuid = otherTokenInstance.getUuid();
        assertThrows(NotFoundException.class,
                () -> cryptographicOperationsService.verifyData(wrongTokenUuid, publicKeyUuid, request),
                "verifyData should reject a key that belongs to a different token instance");
    }

    @Test
    void encryptData_withMismatchedTokenUuid_shouldThrowNotFoundException() throws NotFoundException {
        KeyPairDataResponseDto pair = keyManagementService
                .createKeyPair(tokenInstance.getUuid(), buildRsaCreateKeyRequest("own-encrypt"));
        UUID publicKeyUuid = UUID.fromString(pair.getPublicKeyData().getUuid());

        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherAttributes(buildRsaPkcs1CipherAttributes());
        request.setCipherData(List.of(new CipherRequestData(PLAINTEXT, "item-1")));

        UUID wrongTokenUuid = otherTokenInstance.getUuid();
        assertThrows(NotFoundException.class,
                () -> cryptographicOperationsService.encryptData(wrongTokenUuid, publicKeyUuid, request),
                "encryptData should reject a key that belongs to a different token instance");
    }

    @Test
    void decryptData_withMismatchedTokenUuid_shouldThrowNotFoundException() throws NotFoundException {
        KeyPairDataResponseDto pair = keyManagementService
                .createKeyPair(tokenInstance.getUuid(), buildRsaCreateKeyRequest("own-decrypt"));
        UUID privateKeyUuid = UUID.fromString(pair.getPrivateKeyData().getUuid());

        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherAttributes(buildRsaPkcs1CipherAttributes());
        request.setCipherData(List.of(new CipherRequestData(PLAINTEXT, "item-1")));

        UUID wrongTokenUuid = otherTokenInstance.getUuid();
        assertThrows(NotFoundException.class,
                () -> cryptographicOperationsService.decryptData(wrongTokenUuid, privateKeyUuid, request),
                "decryptData should reject a key that belongs to a different token instance");
    }

    private CreateKeyRequestDto buildRsaCreateKeyRequest(String alias) {
        List<RequestAttribute> attrs = new ArrayList<>();
        attrs.add(buildAliasAttribute(alias));
        attrs.add(buildAlgorithmAttribute(KeyAlgorithm.RSA));

        RequestAttributeV2 sizeAttr = new RequestAttributeV2();
        sizeAttr.setName(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE);
        sizeAttr.setContentType(AttributeContentType.INTEGER);
        sizeAttr.setContent(List.of(new IntegerAttributeContentV2("RSA_2048", 2048)));
        attrs.add(sizeAttr);

        CreateKeyRequestDto req = new CreateKeyRequestDto();
        req.setCreateKeyAttributes(attrs);
        return req;
    }

    private List<RequestAttribute> buildRsaSignatureAttributes() {
        List<RequestAttribute> attrs = new ArrayList<>();

        RequestAttributeV2 schemeAttr = new RequestAttributeV2();
        schemeAttr.setName(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME);
        schemeAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 schemeContent = new StringAttributeContentV2();
        schemeContent.setReference(RsaSignatureScheme.PKCS1_v1_5.getCode());
        schemeContent.setData(RsaSignatureScheme.PKCS1_v1_5.getCode());
        schemeAttr.setContent(List.of(schemeContent));
        attrs.add(schemeAttr);

        RequestAttributeV2 digestAttr = new RequestAttributeV2();
        digestAttr.setName(RsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST);
        digestAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 digestContent = new StringAttributeContentV2();
        digestContent.setReference(DigestAlgorithm.SHA_256.getCode());
        digestContent.setData(DigestAlgorithm.SHA_256.getCode());
        digestAttr.setContent(List.of(digestContent));
        attrs.add(digestAttr);

        return attrs;
    }

    private List<RequestAttribute> buildRsaPkcs1CipherAttributes() {
        List<RequestAttribute> attrs = new ArrayList<>();

        RequestAttributeV2 schemeAttr = new RequestAttributeV2();
        schemeAttr.setName(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME);
        schemeAttr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 schemeContent = new StringAttributeContentV2();
        schemeContent.setReference(RsaEncryptionScheme.PKCS1_v1_5.getCode());
        schemeContent.setData(RsaEncryptionScheme.PKCS1_v1_5.getCode());
        schemeAttr.setContent(List.of(schemeContent));
        attrs.add(schemeAttr);

        return attrs;
    }
}
