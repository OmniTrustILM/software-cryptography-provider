package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.enums.cryptography.KeyType;
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
import com.otilm.api.model.connector.cryptography.operations.data.SignatureResponseData;
import com.otilm.api.model.connector.cryptography.operations.data.VerificationResponseData;
import com.otilm.cp.soft.dao.entity.TokenInstance;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import com.otilm.cp.soft.metrics.ConnectorEvent;
import com.otilm.cp.soft.metrics.ConnectorMetrics;
import com.otilm.cp.soft.model.CachedKeyData;
import com.otilm.cp.soft.model.CachedKeyMaterial;
import com.otilm.cp.soft.model.OperationKey;
import com.otilm.cp.soft.service.CryptographicOperationsService;
import com.otilm.cp.soft.service.KeyDataCacheService;
import com.otilm.cp.soft.service.KeyStoreCacheService;
import com.otilm.cp.soft.util.CipherUtil;
import com.otilm.cp.soft.util.KeyStoreUtil;
import com.otilm.cp.soft.util.PrehashedSignatures;
import com.otilm.cp.soft.util.SecureRandomUtil;
import com.otilm.cp.soft.util.SignatureUtil;
import java.security.PrivateKey;
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
        return connectorMetrics
                .counting(ConnectorEvent.DATA_SIGNED, () -> sign(resolveForOperation(uuid, keyUuid), request),
                        CryptographicOperationsServiceImpl::everyItemSigned);
    }

    private static SignDataResponseDto sign(OperationKey operationKey, SignDataRequestDto request) {
        CachedKeyData key = operationKey.key();

        // check if we are going to sign with private key
        if (key.type() != KeyType.PRIVATE_KEY) {
            throw new CryptographicOperationException("Only private keys can be used for signing.");
        }

        // initialize signature with the algorithm
        Signature signature = SignatureUtil.prepareSignature(key, request.getSignatureAttributes());
        // initialize the signature with the private key
        SignatureUtil.initSigning(signature, key, operationKey.material());

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
        return connectorMetrics
                .counting(ConnectorEvent.SIGNATURE_VERIFIED, () -> verify(resolveForOperation(uuid, keyUuid), request),
                        CryptographicOperationsServiceImpl::everyItemChecked);
    }

    private static VerifyDataResponseDto verify(OperationKey operationKey, VerifyDataRequestDto request) {
        CachedKeyData key = operationKey.key();

        // check if we are going to verify with public key
        if (key.type() != KeyType.PUBLIC_KEY) {
            throw new CryptographicOperationException("Only public keys can be used for verification.");
        }

        // initialize signature with the algorithm
        Signature signature = SignatureUtil.prepareSignature(key, request.getSignatureAttributes());
        SignatureUtil.initVerification(signature, key, operationKey.material());

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
        return connectorMetrics
                .counting(ConnectorEvent.DATA_DECRYPTED, () -> decrypt(resolveForOperation(uuid, keyUuid), request));
    }

    private static DecryptDataResponseDto decrypt(OperationKey operationKey, CipherDataRequestDto request) {
        CachedKeyData key = operationKey.key();

        // check if we are going to decrypt with private key
        if (key.type() != KeyType.PRIVATE_KEY) {
            throw new CryptographicOperationException("Only private keys can be used for decryption.");
        }

        return CipherUtil.decrypt(request, key, operationKey.material());
    }

    @Override
    public EncryptDataResponseDto encryptData(UUID uuid, UUID keyUuid, CipherDataRequestDto request)
            throws NotFoundException {
        return connectorMetrics
                .counting(ConnectorEvent.DATA_ENCRYPTED, () -> encrypt(resolveForOperation(uuid, keyUuid), request));
    }

    private static EncryptDataResponseDto encrypt(OperationKey operationKey, CipherDataRequestDto request) {
        CachedKeyData key = operationKey.key();

        // check if we are going to encrypt with public key
        if (key.type() != KeyType.PUBLIC_KEY) {
            throw new CryptographicOperationException("Only public keys can be used for encryption.");
        }

        return CipherUtil.encrypt(request, key, operationKey.material());
    }

    @Override
    public SignDataResponseDto signData(OperationKey key, SignDataRequestDto request) {
        return connectorMetrics
                .counting(ConnectorEvent.DATA_SIGNED, () -> sign(key, request),
                        CryptographicOperationsServiceImpl::everyItemSigned);
    }

    @Override
    public SignDataResponseDto signDigests(OperationKey key, SignatureAlgorithm algorithm,
            List<SignatureRequestData> digests) {
        return connectorMetrics
                .counting(ConnectorEvent.DATA_SIGNED, () -> signEachDigest(key, algorithm, digests),
                        CryptographicOperationsServiceImpl::everyItemSigned);
    }

    private static SignDataResponseDto signEachDigest(OperationKey operationKey, SignatureAlgorithm algorithm,
            List<SignatureRequestData> digests) {
        CachedKeyData key = operationKey.key();
        if (key.type() != KeyType.PRIVATE_KEY) {
            throw new CryptographicOperationException("Only private keys can be used for signing.");
        }
        PrivateKey privateKey = KeyStoreUtil.getPrivateKey(key, operationKey.material());

        List<SignatureResponseData> signatures = new ArrayList<>();
        for (SignatureRequestData digest : digests) {
            SignatureResponseData signed = new SignatureResponseData();
            signed.setIdentifier(digest.getIdentifier());
            try {
                signed.setData(PrehashedSignatures.sign(algorithm, privateKey, digest.getData()));
            } catch (SignatureException e) {
                signed.setDetails("Signature failed: " + e.getMessage());
            }
            signatures.add(signed);
        }

        SignDataResponseDto response = new SignDataResponseDto();
        response.setSignatures(signatures);
        return response;
    }

    @Override
    public VerifyDataResponseDto verifyData(OperationKey key, VerifyDataRequestDto request) {
        return connectorMetrics
                .counting(ConnectorEvent.SIGNATURE_VERIFIED, () -> verify(key, request),
                        CryptographicOperationsServiceImpl::everyItemChecked);
    }

    @Override
    public DecryptDataResponseDto decryptData(OperationKey key, CipherDataRequestDto request) {
        return connectorMetrics.counting(ConnectorEvent.DATA_DECRYPTED, () -> decrypt(key, request));
    }

    @Override
    public EncryptDataResponseDto encryptData(OperationKey key, CipherDataRequestDto request) {
        return connectorMetrics.counting(ConnectorEvent.DATA_ENCRYPTED, () -> encrypt(key, request));
    }

    private OperationKey resolveForOperation(UUID tokenInstanceUuid, UUID keyUuid) throws NotFoundException {
        CachedKeyMaterial material = keyStoreCacheService.loadKeyMaterial(tokenInstanceUuid);
        CachedKeyData key = keyDataCacheService.getCachedKeyData(keyUuid, material);
        if (!tokenInstanceUuid.equals(key.tokenInstanceUuid())) {
            throw new NotFoundException(TokenInstance.class, tokenInstanceUuid);
        }
        return new OperationKey(key, material);
    }

    private static boolean everyItemSigned(SignDataResponseDto signed) {
        return signed.getSignatures().stream().allMatch(item -> item.getData() != null);
    }

    private static boolean everyItemChecked(VerifyDataResponseDto verified) {
        return verified.getVerifications().stream().allMatch(item -> item.getDetails() == null);
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
