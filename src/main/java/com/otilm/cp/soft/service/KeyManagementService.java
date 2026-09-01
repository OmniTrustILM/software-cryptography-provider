package com.otilm.cp.soft.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.cp.soft.dao.entity.KeyData;

import java.util.List;
import java.util.UUID;

public interface KeyManagementService {

    KeyPairDataResponseDto createKeyPair(UUID uuid, CreateKeyRequestDto request) throws NotFoundException;

    void destroyKey(UUID uuid, UUID keyUuid) throws NotFoundException;

    List<KeyData> listKeyEntities(UUID uuid) throws NotFoundException;

    List<KeyDataResponseDto> listKeys(UUID uuid) throws NotFoundException;

    KeyData getKeyEntity(UUID uuid, UUID keyUuid) throws NotFoundException;

    KeyDataResponseDto getKey(UUID uuid, UUID keyUuid) throws NotFoundException;

}
