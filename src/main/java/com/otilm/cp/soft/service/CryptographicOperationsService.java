package com.otilm.cp.soft.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.connector.cryptography.operations.*;

import java.util.UUID;

public interface CryptographicOperationsService {

    SignDataResponseDto signData(UUID uuid, UUID keyUuid, SignDataRequestDto request) throws NotFoundException;

    VerifyDataResponseDto verifyData(UUID uuid, UUID keyUuid, VerifyDataRequestDto request) throws NotFoundException;

    RandomDataResponseDto randomData(String uuid, RandomDataRequestDto request);

    DecryptDataResponseDto decryptData(UUID uuid, UUID keyUuid, CipherDataRequestDto request) throws NotFoundException;

    EncryptDataResponseDto encryptData(UUID uuid, UUID keyUuid, CipherDataRequestDto request) throws NotFoundException;
}
