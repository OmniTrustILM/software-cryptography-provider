package com.otilm.cp.soft.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.EncryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.RandomDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.RandomDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.data.SignatureRequestData;
import com.otilm.cp.soft.model.OperationKey;
import java.util.List;
import java.util.UUID;

public interface CryptographicOperationsService {

    SignDataResponseDto signData(UUID uuid, UUID keyUuid, SignDataRequestDto request) throws NotFoundException;

    VerifyDataResponseDto verifyData(UUID uuid, UUID keyUuid, VerifyDataRequestDto request) throws NotFoundException;

    RandomDataResponseDto randomData(String uuid, RandomDataRequestDto request);

    DecryptDataResponseDto decryptData(UUID uuid, UUID keyUuid, CipherDataRequestDto request) throws NotFoundException;

    EncryptDataResponseDto encryptData(UUID uuid, UUID keyUuid, CipherDataRequestDto request) throws NotFoundException;

    /** Signs with a key whose material the caller already holds. */
    SignDataResponseDto signData(OperationKey key, SignDataRequestDto request);

    /** Signs digests the caller already computed, without hashing them again, with a key whose material it holds. */
    SignDataResponseDto signDigests(OperationKey key, SignatureAlgorithm algorithm, List<SignatureRequestData> digests);

    /** Verifies with a key whose material the caller already holds. */
    VerifyDataResponseDto verifyData(OperationKey key, VerifyDataRequestDto request);

    /** Decrypts with a key whose material the caller already holds. */
    DecryptDataResponseDto decryptData(OperationKey key, CipherDataRequestDto request);

    /** Encrypts with a key whose material the caller already holds. */
    EncryptDataResponseDto encryptData(OperationKey key, CipherDataRequestDto request);
}
