package com.otilm.cp.soft.api;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.connector.cryptography.KeyManagementController;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.service.AttributeService;
import com.otilm.cp.soft.service.KeyManagementService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
public class KeyManagementControllerImpl implements KeyManagementController {

    private AttributeService attributeService;

    private KeyManagementService keyManagementService;

    @Autowired
    public void setAttributeService(AttributeService attributeService) {
        this.attributeService = attributeService;
    }

    @Autowired
    public void setKeyManagementService(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }


    @Override
    public List<BaseAttribute> listCreateSecretKeyAttributes(String uuid) throws NotFoundException {
        throw new NotSupportedException("Secret keys are not supported.");
    }

    @Override
    public void validateCreateSecretKeyAttributes(String uuid, List<RequestAttribute> attributes) throws NotFoundException, ValidationException {
        throw new NotSupportedException("Secret keys are not supported.");
    }

    @Override
    public KeyDataResponseDto createSecretKey(String uuid, CreateKeyRequestDto request) throws NotFoundException {
        throw new NotSupportedException("Secret keys are not supported.");
    }

    @Override
    public List<BaseAttribute> listCreateKeyPairAttributes(String uuid) throws NotFoundException {
        return attributeService.getCreateKeyAttributes(uuid);
    }

    @Override
    public void validateCreateKeyPairAttributes(String uuid, List<RequestAttribute> attributes) throws NotFoundException, ValidationException {
        attributeService.validateCreateKeyAttributes(uuid, attributes);
    }

    @Override
    public KeyPairDataResponseDto createKeyPair(String uuid, CreateKeyRequestDto request) throws NotFoundException {
        return keyManagementService.createKeyPair(UUID.fromString(uuid), request);
    }

    @Override
    public List<KeyDataResponseDto> listKeys(String uuid) throws NotFoundException {
        return keyManagementService.listKeys(UUID.fromString(uuid));
    }

    @Override
    public KeyDataResponseDto getKey(String uuid, String keyUuid) throws NotFoundException {
        return keyManagementService.getKey(UUID.fromString(uuid), UUID.fromString(keyUuid));
    }

    @Override
    public void destroyKey(String uuid, String keyUuid) throws NotFoundException {
        keyManagementService.destroyKey(UUID.fromString(uuid), UUID.fromString(keyUuid));
    }

}
