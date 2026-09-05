package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.EncryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.RandomDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.connector.cryptography.v2.KeyScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.CipherDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.DecryptDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataResponseV2Dto;
import com.otilm.cp.soft.attribute.OperationAttributes;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.model.KeyContext;
import com.otilm.cp.soft.model.TokenContext;
import com.otilm.cp.soft.service.CryptographicOperationsService;
import com.otilm.cp.soft.service.CryptographicOperationsV2Service;
import com.otilm.cp.soft.service.KeyContextService;
import com.otilm.cp.soft.service.TokenContextService;
import com.otilm.cp.soft.util.OperationDataMapper;
import jakarta.transaction.Transactional;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * The cryptographic operations under the V2 interfaces, performed on the same stored keys the V1 interfaces serve.
 *
 * <p>
 * Every operation completes inline. The work itself is unchanged: this resolves the token and key a request addressed
 * through its attributes and metadata, and hands the operation to the same code the V1 interfaces use, so both
 * interfaces sign and encrypt identically.
 * </p>
 */
@Service
@Transactional
public class CryptographicOperationsV2ServiceImpl implements CryptographicOperationsV2Service {

    private CryptographicOperationsService cryptographicOperationsService;

    private KeyContextService keyContextService;

    private TokenContextService tokenContextService;

    @Override
    public List<BaseAttribute> signatureAttributes(KeyScopedRequestV2Dto request) {
        return OperationAttributes.signatureAttributes(key(request).key().getAlgorithm());
    }

    @Override
    public List<BaseAttribute> cipherAttributes(KeyScopedRequestV2Dto request) {
        return OperationAttributes.cipherAttributes(key(request).key().getAlgorithm());
    }

    @Override
    public List<BaseAttribute> randomAttributes(TokenProfileScopedRequestV2Dto request) {
        tokenContextService.locate(request.getTokenAttributes());
        return List.of();
    }

    @Override
    public SignDataResponseV2Dto signData(SignDataRequestV2Dto request) {
        KeyContext key = key(request);

        SignDataRequestDto signing = new SignDataRequestDto();
        signing.setSignatureAttributes(request.getSignatureAttributes());
        signing.setData(OperationDataMapper.toSignatureRequests(request.getData()));

        SignDataResponseDto signed = perform(() -> cryptographicOperationsService
                .signData(key.token().instance().getUuid(), key.key().getUuid(), signing));

        SignDataResponseV2Dto response = new SignDataResponseV2Dto();
        response.setSignatures(OperationDataMapper.toSignatureData(signed.getSignatures()));
        return response;
    }

    @Override
    public VerifyDataResponseV2Dto verifyData(VerifyDataRequestV2Dto request) {
        KeyContext key = key(request);

        VerifyDataRequestDto verification = new VerifyDataRequestDto();
        verification.setSignatureAttributes(request.getSignatureAttributes());
        verification.setData(OperationDataMapper.toSignatureRequests(request.getData()));
        verification
                .setSignatures(
                        OperationDataMapper.toSignatureRequestsPairedWith(request.getData(), request.getSignatures()));

        VerifyDataResponseDto verified = perform(() -> cryptographicOperationsService
                .verifyData(key.token().instance().getUuid(), key.key().getUuid(), verification));

        VerifyDataResponseV2Dto response = new VerifyDataResponseV2Dto();
        response.setVerifications(OperationDataMapper.toVerifications(verified.getVerifications()));
        return response;
    }

    @Override
    public EncryptDataResponseV2Dto encryptData(CipherDataRequestV2Dto request) {
        KeyContext key = key(request);

        EncryptDataResponseDto encrypted = perform(() -> cryptographicOperationsService
                .encryptData(key.token().instance().getUuid(), key.key().getUuid(), cipher(request)));

        EncryptDataResponseV2Dto response = new EncryptDataResponseV2Dto();
        response.setEncryptedData(OperationDataMapper.toCipherData(encrypted.getEncryptedData()));
        return response;
    }

    @Override
    public DecryptDataResponseV2Dto decryptData(CipherDataRequestV2Dto request) {
        KeyContext key = key(request);

        DecryptDataResponseDto decrypted = perform(() -> cryptographicOperationsService
                .decryptData(key.token().instance().getUuid(), key.key().getUuid(), cipher(request)));

        DecryptDataResponseV2Dto response = new DecryptDataResponseV2Dto();
        response.setDecryptedData(OperationDataMapper.toCipherData(decrypted.getDecryptedData()));
        return response;
    }

    @Override
    public RandomDataResponseV2Dto randomData(RandomDataRequestV2Dto request) {
        TokenContext token = tokenContextService.resolve(request.getTokenAttributes());

        RandomDataRequestDto random = new RandomDataRequestDto();
        random.setLength(request.getLength());
        random.setAttributes(request.getOperationAttributes());

        RandomDataResponseV2Dto response = new RandomDataResponseV2Dto();
        response
                .setData(cryptographicOperationsService
                        .randomData(token.instance().getUuid().toString(), random)
                        .getData());
        return response;
    }

    private static CipherDataRequestDto cipher(CipherDataRequestV2Dto request) {
        CipherDataRequestDto cipher = new CipherDataRequestDto();
        cipher.setCipherAttributes(request.getCipherAttributes());
        cipher.setCipherData(OperationDataMapper.toCipherRequests(request.getCipherData()));
        return cipher;
    }

    private KeyContext key(KeyScopedRequestV2Dto request) {
        return keyContextService.resolve(request.getTokenAttributes(), request.getKeyMeta());
    }

    /** The operations report a missing key as a checked absence; the V2 interfaces answer it as the contract states. */
    private static <T> T perform(Operation<T> operation) {
        try {
            return operation.run();
        } catch (NotFoundException e) {
            throw new ResourceMissingException("The addressed key does not exist", e);
        }
    }

    @FunctionalInterface
    private interface Operation<T> {

        T run() throws NotFoundException;
    }

    @Autowired
    public void setCryptographicOperationsService(CryptographicOperationsService cryptographicOperationsService) {
        this.cryptographicOperationsService = cryptographicOperationsService;
    }

    @Autowired
    public void setKeyContextService(KeyContextService keyContextService) {
        this.keyContextService = keyContextService;
    }

    @Autowired
    public void setTokenContextService(TokenContextService tokenContextService) {
        this.tokenContextService = tokenContextService;
    }
}
