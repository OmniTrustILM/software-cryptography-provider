package com.otilm.cp.soft.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.util.ImportedKeyMaterial;
import java.util.List;
import java.util.UUID;

public interface KeyManagementService {

    KeyPairDataResponseDto createKeyPair(UUID uuid, CreateKeyRequestDto request) throws NotFoundException;

    /**
     * Stores a key the platform sent into a token, the way a generated one is stored.
     *
     * @param uuid the token instance identifier
     * @param alias the alias the key is known by in the token
     * @param material the key pair read out of the protected material
     * @return the stored key pair
     * @throws NotFoundException when no such token instance exists
     */
    KeyPairDataResponseDto storeImportedKeyPair(UUID uuid, String alias, ImportedKeyMaterial material)
            throws NotFoundException;

    void destroyKey(UUID uuid, UUID keyUuid) throws NotFoundException;

    List<KeyData> listKeyEntities(UUID uuid) throws NotFoundException;

    List<KeyDataResponseDto> listKeys(UUID uuid) throws NotFoundException;

    KeyData getKeyEntity(UUID uuid, UUID keyUuid) throws NotFoundException;

    KeyDataResponseDto getKey(UUID uuid, UUID keyUuid) throws NotFoundException;

}
