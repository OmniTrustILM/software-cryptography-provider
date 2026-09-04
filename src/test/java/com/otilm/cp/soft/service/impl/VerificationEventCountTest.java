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
import com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.otilm.api.model.connector.cryptography.operations.data.VerificationResponseData;
import com.otilm.cp.soft.attribute.EcdsaKeyAttributes;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.collection.EcdsaCurveName;
import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.dao.repository.TokenInstanceRepository;
import com.otilm.cp.soft.service.CryptographicOperationsService;
import com.otilm.cp.soft.service.KeyManagementService;
import com.otilm.cp.soft.util.KeyStoreUtil;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * A signature the key technology found invalid was still verified, and one it could not check at all was not. Both are
 * answered without failing the request, so only the count tells an operator them apart.
 *
 * <p>
 * Not transactional: work inside a transaction is counted once that transaction settles, and a test transaction is
 * rolled back, so a test that held one could only ever see the count of work undone.
 * </p>
 */
@SpringBootTest
class VerificationEventCountTest {

    private static final String PASSWORD = "123";

    private static final DigestAlgorithm DIGEST = DigestAlgorithm.SHA_256;

    private KeyManagementService keyManagementService;

    private CryptographicOperationsService cryptographicOperationsService;

    private TokenInstanceRepository tokenInstanceRepository;

    private PrometheusMeterRegistry registry;

    private UUID token;

    private UUID privateKey;

    private UUID publicKey;

    @BeforeEach
    void createAKeyToVerifyWith() throws NotFoundException {
        TokenInstance instance = new TokenInstance();
        instance.setCode(PASSWORD);
        instance.setData(KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD));
        token = tokenInstanceRepository.save(instance).getUuid();

        CreateKeyRequestDto creation = new CreateKeyRequestDto();
        creation.setCreateKeyAttributes(ecdsaKeyAttributes("verification-count-" + UUID.randomUUID()));
        KeyPairDataResponseDto pair = keyManagementService.createKeyPair(token, creation);
        privateKey = UUID.fromString(pair.getPrivateKeyData().getUuid());
        publicKey = UUID.fromString(pair.getPublicKeyData().getUuid());
    }

    /** An invalid signature is an answer, so the verification it came from did what it was asked. */
    @Test
    void countsAVerificationThatFoundASignatureInvalidAsHavingWorked() throws NotFoundException {
        // given
        byte[] signature = sign("what was signed".getBytes());
        double before = counted("success");

        // when
        VerificationResponseData verified = verify("something else".getBytes(), signature);

        // then
        assertFalse(verified.isResult(), "the signature is over other data");
        assertNull(verified.getDetails(), "the verification itself was performed");
        assertEquals(before + 1, counted("success"));
    }

    /** A signature that cannot be read at all is answered with why, and no verification happened. */
    @Test
    void countsAVerificationThatCouldNotBePerformedAsHavingFailed() throws NotFoundException {
        // given
        double before = counted("error");

        // when
        VerificationResponseData verified = verify("what was signed".getBytes(), "not a signature".getBytes());

        // then
        assertNotNull(verified.getDetails(), "the verification could not be performed");
        assertEquals(before + 1, counted("error"));
    }

    private byte[] sign(byte[] data) throws NotFoundException {
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(signatureAttributes());
        request.setData(List.of(new SignatureRequestData(data, "item-1")));
        return cryptographicOperationsService.signData(token, privateKey, request).getSignatures().get(0).getData();
    }

    private VerificationResponseData verify(byte[] data, byte[] signature) throws NotFoundException {
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatureAttributes(signatureAttributes());
        request.setData(List.of(new SignatureRequestData(data, "item-1")));
        request.setSignatures(List.of(new SignatureRequestData(signature, "item-1")));
        VerifyDataResponseDto response = cryptographicOperationsService.verifyData(token, publicKey, request);
        return response.getVerifications().get(0);
    }

    private double counted(String outcome) {
        return registry
                .find("connector_events_total")
                .tags("event", "signature_verified", "outcome", outcome)
                .counter()
                .count();
    }

    private static List<RequestAttribute> ecdsaKeyAttributes(String alias) {
        return List
                .of(stringAttribute(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS, alias),
                        stringAttribute(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, KeyAlgorithm.ECDSA.getCode()),
                        stringAttribute(EcdsaKeyAttributes.ATTRIBUTE_DATA_ECDSA_CURVE,
                                EcdsaCurveName.secp256r1.getName()));
    }

    private static List<RequestAttribute> signatureAttributes() {
        return List.of(stringAttribute(EcdsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST, DIGEST.getCode()));
    }

    private static RequestAttributeV2 stringAttribute(String name, String value) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 content = new StringAttributeContentV2();
        content.setReference(value);
        content.setData(value);
        attribute.setContent(List.of(content));
        return attribute;
    }

    @Autowired
    void setKeyManagementService(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    @Autowired
    void setCryptographicOperationsService(CryptographicOperationsService cryptographicOperationsService) {
        this.cryptographicOperationsService = cryptographicOperationsService;
    }

    @Autowired
    void setTokenInstanceRepository(TokenInstanceRepository tokenInstanceRepository) {
        this.tokenInstanceRepository = tokenInstanceRepository;
    }

    @Autowired
    void setRegistry(PrometheusMeterRegistry registry) {
        this.registry = registry;
    }
}
