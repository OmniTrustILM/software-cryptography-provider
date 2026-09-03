package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.value.SpkiKeyValue;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.DestroyKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.cp.soft.dao.entity.KeyCreationRecord;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.dao.repository.KeyCreationRecordRepository;
import com.otilm.cp.soft.dao.repository.KeyDataRepository;
import com.otilm.cp.soft.exception.ConcurrentRequestException;
import com.otilm.cp.soft.exception.KeyManagementException;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.OperationConflictException;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.model.KeyContext;
import com.otilm.cp.soft.model.TokenContext;
import com.otilm.cp.soft.service.AttributeService;
import com.otilm.cp.soft.service.CryptographicKeyV2Service;
import com.otilm.cp.soft.service.KeyContextService;
import com.otilm.cp.soft.service.KeyManagementService;
import com.otilm.cp.soft.service.TokenContextService;
import com.otilm.cp.soft.util.RequestFingerprint;
import jakarta.transaction.Transactional;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

/**
 * The key lifecycle under the V2 interfaces, over the same stored keys the V1 interfaces serve.
 *
 * <p>
 * Creation is idempotent by the identifier the request carries: a caller that lost the response repeats the request and
 * is given the key the first attempt made. The same identifier on a different request is a conflict, since answering
 * with the first key would silently ignore what the second one asked for.
 * </p>
 *
 * <p>
 * Only synchronous execution is offered. Every operation here completes inline, so a request for asynchronous
 * processing is refused rather than accepted and immediately finished, which would leave the caller polling for an
 * operation that no longer exists.
 * </p>
 */
@Service
@Transactional
public class CryptographicKeyV2ServiceImpl implements CryptographicKeyV2Service {

    private static final Logger logger = LoggerFactory.getLogger(CryptographicKeyV2ServiceImpl.class);

    private AttributeService attributeService;

    private KeyContextService keyContextService;

    private KeyCreationRecordRepository keyCreationRecordRepository;

    private KeyDataRepository keyDataRepository;

    private KeyManagementService keyManagementService;

    private TokenContextService tokenContextService;

    @Override
    public List<BaseAttribute> createKeyAttributes(CreateKeyAttributesRequestV2Dto request) {
        requireKeyPair(request.getKeyRequestType());
        TokenContext token = tokenContextService.resolve(request.getTokenAttributes());
        try {
            return attributeService.getCreateKeyAttributes(token.instance().getUuid().toString());
        } catch (NotFoundException e) {
            throw new ResourceMissingException("The addressed token does not exist", e);
        }
    }

    @Override
    public KeyPairDataResponseV2Dto createKey(CreateKeyRequestV2Dto request) {
        requireKeyPair(request.getKeyRequestType());
        requireSynchronous(request.getExecutionMode());

        TokenContext token = tokenContextService.resolve(request.getTokenAttributes());
        // The resolved token stands for the context the request carried. The context itself carries the code that
        // opens the token, and the fingerprint is stored, so what identifies the token is fingerprinted instead.
        String fingerprint = RequestFingerprint
                .of(request.getKeyRequestType(), request.getExecutionMode(), token.instance().getUuid(),
                        request.getTokenProfileAttributes(), request.getKeyUsages(), request.getCreateKeyAttributes());

        Optional<KeyCreationRecord> earlier = keyCreationRecordRepository.findByCreationId(request.getKeyCreationId());
        if (earlier.isPresent()) {
            return replay(earlier.get(), fingerprint);
        }

        CreateKeyRequestDto creation = new CreateKeyRequestDto();
        creation.setTokenProfileAttributes(request.getTokenProfileAttributes());
        creation.setCreateKeyAttributes(request.getCreateKeyAttributes());

        KeyPairDataResponseDto created;
        try {
            created = keyManagementService.createKeyPair(token.instance().getUuid(), creation);
        } catch (NotFoundException e) {
            throw new ResourceMissingException("The addressed token does not exist", e);
        }
        remember(request.getKeyCreationId(), token, fingerprint, created);

        return keyPair(key(created.getPublicKeyData().getUuid()), key(created.getPrivateKeyData().getUuid()));
    }

    @Override
    public void destroyKey(DestroyKeyRequestV2Dto request) {
        requireSynchronous(request.getExecutionMode());

        KeyContext key = keyContextService.resolve(request.getTokenAttributes(), request.getKeyMeta());
        try {
            keyManagementService.destroyKey(key.token().instance().getUuid(), key.key().getUuid());
        } catch (NotFoundException e) {
            throw new ResourceMissingException("The addressed key does not exist", e);
        }
    }

    /**
     * Answers a repeated request with the key its first attempt made, or refuses a different request wearing its id.
     */
    private KeyPairDataResponseV2Dto replay(KeyCreationRecord earlier, String fingerprint) {
        if (!earlier.getRequestFingerprint().equals(fingerprint)) {
            throw new OperationConflictException(
                    "Key creation " + earlier.getCreationId() + " already identifies a different request");
        }
        logger.debug("Answering a repeated key creation {} with the key it made", earlier.getCreationId());
        return keyPair(key(earlier.getPublicKeyUuid()), key(earlier.getPrivateKeyUuid()));
    }

    /**
     * Records what this attempt produced. Losing a race on the identifier means another request is recording the same
     * creation, so this attempt is rolled back and the caller repeating the request is answered with the key that one
     * made, which is what the identifier promises.
     */
    private void remember(String creationId, TokenContext token, String fingerprint, KeyPairDataResponseDto created) {
        KeyCreationRecord attempt = new KeyCreationRecord();
        attempt.setCreationId(creationId);
        attempt.setTokenInstanceUuid(token.instance().getUuid());
        attempt.setRequestFingerprint(fingerprint);
        attempt.setPublicKeyUuid(UUID.fromString(created.getPublicKeyData().getUuid()));
        attempt.setPrivateKeyUuid(UUID.fromString(created.getPrivateKeyData().getUuid()));
        attempt.setCreatedAt(OffsetDateTime.now());
        try {
            keyCreationRecordRepository.saveAndFlush(attempt);
        } catch (DataIntegrityViolationException e) {
            throw new ConcurrentRequestException("Key creation " + creationId + " is being recorded by another request",
                    e);
        }
    }

    private KeyData key(String uuid) {
        return key(UUID.fromString(uuid));
    }

    private KeyData key(UUID uuid) {
        return keyDataRepository
                .findByUuid(uuid)
                .orElseThrow(() -> new KeyManagementException("A key this provider created is no longer stored"));
    }

    private KeyPairDataResponseV2Dto keyPair(KeyData publicKey, KeyData privateKey) {
        KeyPairDataResponseV2Dto response = new KeyPairDataResponseV2Dto();
        response.setPublicKeyData(publicKeyData(publicKey));
        response.setPrivateKeyData(privateKeyData(privateKey));
        return response;
    }

    private PublicKeyDataResponseV2Dto publicKeyData(KeyData key) {
        PublicKeyDataV2Dto descriptor = new PublicKeyDataV2Dto();
        descriptor.setAlgorithm(key.getAlgorithm());
        descriptor.setLength(key.getLength());
        descriptor.setPublicKeySpki(spki(key));

        PublicKeyDataResponseV2Dto response = new PublicKeyDataResponseV2Dto();
        response.setKeyMeta(keyContextService.publish(key));
        response.setKeyData(descriptor);
        return response;
    }

    private PrivateKeyDataResponseV2Dto privateKeyData(KeyData key) {
        PrivateKeyDataV2Dto descriptor = new PrivateKeyDataV2Dto();
        descriptor.setAlgorithm(key.getAlgorithm());
        descriptor.setLength(key.getLength());

        PrivateKeyDataResponseV2Dto response = new PrivateKeyDataResponseV2Dto();
        response.setKeyMeta(keyContextService.publish(key));
        response.setKeyData(descriptor);
        return response;
    }

    /** The stored public key, whose value is the SPKI this provider recorded when the key was created. */
    private static byte[] spki(KeyData key) {
        if (key.getValue() instanceof SpkiKeyValue spki && spki.getValue() != null) {
            return Base64.getDecoder().decode(spki.getValue());
        }
        return null;
    }

    private static void requireKeyPair(KeyRequestType keyRequestType) {
        if (keyRequestType != KeyRequestType.KEY_PAIR) {
            throw new NotSupportedException("Secret keys are not supported.");
        }
    }

    private static void requireSynchronous(OperationExecutionMode executionMode) {
        if (executionMode != OperationExecutionMode.SYNCHRONOUS) {
            throw new NotSupportedException("Asynchronous execution is not supported.");
        }
    }

    @Autowired
    public void setAttributeService(AttributeService attributeService) {
        this.attributeService = attributeService;
    }

    @Autowired
    public void setKeyContextService(KeyContextService keyContextService) {
        this.keyContextService = keyContextService;
    }

    @Autowired
    public void setKeyCreationRecordRepository(KeyCreationRecordRepository keyCreationRecordRepository) {
        this.keyCreationRecordRepository = keyCreationRecordRepository;
    }

    @Autowired
    public void setKeyDataRepository(KeyDataRepository keyDataRepository) {
        this.keyDataRepository = keyDataRepository;
    }

    @Autowired
    public void setKeyManagementService(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    @Autowired
    public void setTokenContextService(TokenContextService tokenContextService) {
        this.tokenContextService = tokenContextService;
    }
}
