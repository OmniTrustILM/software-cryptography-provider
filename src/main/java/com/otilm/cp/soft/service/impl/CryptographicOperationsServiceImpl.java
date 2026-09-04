package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.enums.cryptography.KeyType;
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
import com.otilm.api.model.connector.cryptography.operations.data.SignatureResponseData;
import com.otilm.api.model.connector.cryptography.operations.data.VerificationResponseData;
import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import com.otilm.cp.soft.metrics.ConnectorEvent;
import com.otilm.cp.soft.metrics.ConnectorMetrics;
import com.otilm.cp.soft.model.CachedKeyData;
import com.otilm.cp.soft.model.CachedKeyMaterial;
import com.otilm.cp.soft.service.CryptographicOperationsService;
import com.otilm.cp.soft.service.KeyDataCacheService;
import com.otilm.cp.soft.service.KeyStoreCacheService;
import com.otilm.cp.soft.util.CipherUtil;
import com.otilm.cp.soft.util.SecureRandomUtil;
import com.otilm.cp.soft.util.SignatureUtil;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CryptographicOperationsServiceImpl implements CryptographicOperationsService {
    private KeyDataCacheService keyDataCacheService;
    private KeyStoreCacheService keyStoreCacheService;
    private ConnectorMetrics connectorMetrics;

    @Override
    public SignDataResponseDto signData(UUID uuid, UUID keyUuid, SignDataRequestDto request) throws NotFoundException {
        // An item the key technology could not sign is answered without a signature rather than by failing, and a
        // request answered that way did not do what it was asked.
        return connectorMetrics
                .counting(ConnectorEvent.DATA_SIGNED, () -> sign(uuid, keyUuid, request),
                        signed -> signed.getSignatures().stream().allMatch(item -> item.getData() != null));
    }

    private SignDataResponseDto sign(UUID uuid, UUID keyUuid, SignDataRequestDto request) throws NotFoundException {
        CachedKeyData key = keyDataCacheService.getCachedKeyData(keyUuid);

        if (!uuid.equals(key.tokenInstanceUuid())) {
            throw new NotFoundException(TokenInstance.class, uuid);
        }

        // check if we are going to sign with private key
        if (key.type() != KeyType.PRIVATE_KEY) {
            throw new CryptographicOperationException("Only private keys can be used for signing.");
        }

        CachedKeyMaterial material = keyStoreCacheService.loadKeyMaterial(key.tokenInstanceUuid());
        // initialize signature with the algorithm
        Signature signature = SignatureUtil.prepareSignature(key, request.getSignatureAttributes());
        // initialize the signature with the private key
        SignatureUtil.initSigning(signature, key, material);

        // sign the data, it can be a list, so we need to iterate over it
        SignDataResponseDto response = new SignDataResponseDto();
        List<SignatureResponseData> signatures = new ArrayList<>();

        request.getData().forEach(data -> {
            SignatureResponseData signatureResponseData = new SignatureResponseData();
            signatureResponseData.setIdentifier(data.getIdentifier());
            try {
                signatureResponseData.setData(SignatureUtil.signData(signature, data.getData()));
            } catch (SignatureException e) {
                signatureResponseData.setDetails("Signature failed: " + e.getMessage());
            }
            signatures.add(signatureResponseData);
        });

        response.setSignatures(signatures);
        return response;
    }

    @Override
    public VerifyDataResponseDto verifyData(UUID uuid, UUID keyUuid, VerifyDataRequestDto request)
            throws NotFoundException {
        return connectorMetrics.counting(ConnectorEvent.SIGNATURE_VERIFIED, () -> verify(uuid, keyUuid, request));
    }

    private VerifyDataResponseDto verify(UUID uuid, UUID keyUuid, VerifyDataRequestDto request)
            throws NotFoundException {
        CachedKeyData key = keyDataCacheService.getCachedKeyData(keyUuid);

        if (!uuid.equals(key.tokenInstanceUuid())) {
            throw new NotFoundException(TokenInstance.class, uuid);
        }

        // check if we are going to verify with public key
        if (key.type() != KeyType.PUBLIC_KEY) {
            throw new CryptographicOperationException("Only public keys can be used for verification.");
        }

        CachedKeyMaterial material = keyStoreCacheService.loadKeyMaterial(key.tokenInstanceUuid());
        // initialize signature with the algorithm
        Signature signature = SignatureUtil.prepareSignature(key, request.getSignatureAttributes());
        // initialize the signature with the private key
        SignatureUtil.initVerification(signature, key, material);

        // verify the data, it can be a list, so we need to iterate over it
        VerifyDataResponseDto response = new VerifyDataResponseDto();
        List<VerificationResponseData> verifications = new ArrayList<>();

        Iterator<SignatureRequestData> signIterator = request.getSignatures().iterator();
        Iterator<SignatureRequestData> dataIterator = request.getData().iterator();

        while (dataIterator.hasNext() && signIterator.hasNext()) {
            SignatureRequestData sign = signIterator.next();
            SignatureRequestData data = dataIterator.next();

            VerificationResponseData verificationResponseData = new VerificationResponseData();
            verificationResponseData.setIdentifier(sign.getIdentifier());
            try {
                verificationResponseData.setResult(SignatureUtil.verifyData(signature, data.getData(), sign.getData()));
            } catch (SignatureException e) {
                verificationResponseData.setDetails("Verification failed: " + e.getMessage());
            }
            verifications.add(verificationResponseData);
        }

        response.setVerifications(verifications);
        return response;
    }

    @Override
    public RandomDataResponseDto randomData(String uuid, RandomDataRequestDto request) {
        return connectorMetrics.counting(ConnectorEvent.RANDOM_GENERATED, () -> random(request));
    }

    private static RandomDataResponseDto random(RandomDataRequestDto request) {
        SecureRandom secureRandom = SecureRandomUtil.prepareSecureRandom("DEFAULT", BouncyCastleProvider.PROVIDER_NAME);
        byte[] bytes = new byte[request.getLength()];
        secureRandom.nextBytes(bytes);

        RandomDataResponseDto response = new RandomDataResponseDto();
        response.setData(bytes);
        return response;
    }

    @Override
    public DecryptDataResponseDto decryptData(UUID uuid, UUID keyUuid, CipherDataRequestDto request)
            throws NotFoundException {
        return connectorMetrics.counting(ConnectorEvent.DATA_DECRYPTED, () -> decrypt(uuid, keyUuid, request));
    }

    private DecryptDataResponseDto decrypt(UUID uuid, UUID keyUuid, CipherDataRequestDto request)
            throws NotFoundException {
        CachedKeyData key = keyDataCacheService.getCachedKeyData(keyUuid);

        if (!uuid.equals(key.tokenInstanceUuid())) {
            throw new NotFoundException(TokenInstance.class, uuid);
        }

        // check if we are going to decrypt with private key
        if (key.type() != KeyType.PRIVATE_KEY) {
            throw new CryptographicOperationException("Only private keys can be used for decryption.");
        }

        CachedKeyMaterial material = keyStoreCacheService.loadKeyMaterial(key.tokenInstanceUuid());
        return CipherUtil.decrypt(request, key, material);
    }

    @Override
    public EncryptDataResponseDto encryptData(UUID uuid, UUID keyUuid, CipherDataRequestDto request)
            throws NotFoundException {
        return connectorMetrics.counting(ConnectorEvent.DATA_ENCRYPTED, () -> encrypt(uuid, keyUuid, request));
    }

    private EncryptDataResponseDto encrypt(UUID uuid, UUID keyUuid, CipherDataRequestDto request)
            throws NotFoundException {
        CachedKeyData key = keyDataCacheService.getCachedKeyData(keyUuid);

        if (!uuid.equals(key.tokenInstanceUuid())) {
            throw new NotFoundException(TokenInstance.class, uuid);
        }

        // check if we are going to encrypt with public key
        if (key.type() != KeyType.PUBLIC_KEY) {
            throw new CryptographicOperationException("Only public keys can be used for encryption.");
        }

        CachedKeyMaterial material = keyStoreCacheService.loadKeyMaterial(key.tokenInstanceUuid());
        return CipherUtil.encrypt(request, key, material);
    }

    @Autowired
    public void setKeyDataCacheService(KeyDataCacheService keyDataCacheService) {
        this.keyDataCacheService = keyDataCacheService;
    }

    @Autowired
    public void setConnectorMetrics(ConnectorMetrics connectorMetrics) {
        this.connectorMetrics = connectorMetrics;
    }

    @Autowired
    public void setKeyStoreCacheService(KeyStoreCacheService keyStoreCacheService) {
        this.keyStoreCacheService = keyStoreCacheService;
    }
}
