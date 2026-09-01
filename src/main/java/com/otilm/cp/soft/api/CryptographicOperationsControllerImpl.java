package com.otilm.cp.soft.api;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.connector.cryptography.CryptographicOperationsController;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.EncryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.RandomDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.RandomDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataResponseDto;
import com.otilm.cp.soft.service.CryptographicOperationsService;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CryptographicOperationsControllerImpl implements CryptographicOperationsController {

    private CryptographicOperationsService cryptographicOperationsService;

    @Autowired
    public void setCryptographicOperationsService(CryptographicOperationsService cryptographicOperationsService) {
        this.cryptographicOperationsService = cryptographicOperationsService;
    }

    @Override
    public EncryptDataResponseDto encryptData(String uuid, String keyUuid, CipherDataRequestDto request)
            throws NotFoundException {
        return cryptographicOperationsService.encryptData(UUID.fromString(uuid), UUID.fromString(keyUuid), request);
    }

    @Override
    public DecryptDataResponseDto decryptData(String uuid, String keyUuid, CipherDataRequestDto request)
            throws NotFoundException {
        return cryptographicOperationsService.decryptData(UUID.fromString(uuid), UUID.fromString(keyUuid), request);
    }

    @Override
    public SignDataResponseDto signData(String uuid, String keyUuid, SignDataRequestDto request)
            throws NotFoundException {
        return cryptographicOperationsService.signData(UUID.fromString(uuid), UUID.fromString(keyUuid), request);
    }

    @Override
    public VerifyDataResponseDto verifyData(String uuid, String keyUuid, VerifyDataRequestDto request)
            throws NotFoundException {
        return cryptographicOperationsService.verifyData(UUID.fromString(uuid), UUID.fromString(keyUuid), request);
    }

    @Override
    public List<BaseAttribute> listRandomAttributes(String uuid) throws NotFoundException {
        return List.of();
    }

    @Override
    public void validateRandomAttributes(String uuid, List<RequestAttribute> attributes)
            throws NotFoundException, ValidationException {
        // nothing to validate
    }

    @Override
    public RandomDataResponseDto randomData(String uuid, RandomDataRequestDto request) throws NotFoundException {
        return cryptographicOperationsService.randomData(uuid, request);
    }

}
