package com.otilm.cp.soft.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.connector.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.EncryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.RandomDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.RandomDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataResponseDto;
import java.util.UUID;

public interface CryptographicOperationsService {

    SignDataResponseDto signData(UUID uuid, UUID keyUuid, SignDataRequestDto request) throws NotFoundException;

    VerifyDataResponseDto verifyData(UUID uuid, UUID keyUuid, VerifyDataRequestDto request) throws NotFoundException;

    RandomDataResponseDto randomData(String uuid, RandomDataRequestDto request);

    DecryptDataResponseDto decryptData(UUID uuid, UUID keyUuid, CipherDataRequestDto request) throws NotFoundException;

    EncryptDataResponseDto encryptData(UUID uuid, UUID keyUuid, CipherDataRequestDto request) throws NotFoundException;
}
