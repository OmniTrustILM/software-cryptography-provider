package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.common.v2.OperationStatus;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.value.SpkiKeyValue;
import com.otilm.api.model.connector.cryptography.v2.KeyScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.DestroyKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportKeyResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportableKeyTypeV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyResultRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportableKeyTypeV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyExportableAttribute;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairOperationStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.material.EncryptedKeyMaterialV2Dto;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.dao.repository.KeyDataRepository;
import com.otilm.cp.soft.exception.ConcurrentRequestException;
import com.otilm.cp.soft.exception.KeyManagementException;
import com.otilm.cp.soft.exception.KeyMaterialMismatchException;
import com.otilm.cp.soft.exception.KeyNotExportableException;
import com.otilm.cp.soft.exception.KeyTypeNotExportableException;
import com.otilm.cp.soft.exception.KeyTypeNotImportableException;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.OperationConflictException;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.metrics.ConnectorEvent;
import com.otilm.cp.soft.metrics.ConnectorMetrics;
import com.otilm.cp.soft.model.KeyContext;
import com.otilm.cp.soft.model.TokenContext;
import com.otilm.cp.soft.service.AttributeService;
import com.otilm.cp.soft.service.CryptographicKeyV2Service;
import com.otilm.cp.soft.service.KeyContextService;
import com.otilm.cp.soft.service.KeyManagementService;
import com.otilm.cp.soft.service.TokenContextService;
import com.otilm.cp.soft.util.ExportedKeyMaterial;
import com.otilm.cp.soft.util.ImportedKeyMaterial;
import com.otilm.cp.soft.util.KeyStoreUtil;
import com.otilm.cp.soft.util.RequestFingerprint;
import jakarta.transaction.Transactional;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
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

    /**
     * The algorithms accepted as imported material, which is every algorithm this connector can generate. A secret key
     * is not among them: neither interface generation offers one.
     */
    private static final Set<KeyAlgorithm> IMPORTABLE_ALGORITHMS = Set
            .of(KeyAlgorithm.RSA, KeyAlgorithm.ECDSA, KeyAlgorithm.FALCON, KeyAlgorithm.MLDSA, KeyAlgorithm.SLHDSA,
                    KeyAlgorithm.MLKEM);

    private AttributeService attributeService;

    private ConnectorMetrics connectorMetrics;

    private KeyContextService keyContextService;

    private KeyDataRepository keyDataRepository;

    private KeyManagementService keyManagementService;

    private TokenContextService tokenContextService;

    @Override
    public List<BaseAttribute> createKeyAttributes(CreateKeyAttributesRequestV2Dto request) {
        requireKeyPair(request.getKeyRequestType());
        TokenContext token = tokenContextService.resolve(request.getTokenAttributes());
        try {
            // The exportable intent is added on top of what both generations publish, since a v1 caller neither
            // states it nor is answered by anything that reads it.
            List<BaseAttribute> attributes = new ArrayList<>(
                    attributeService.getCreateKeyAttributes(token.instance().getUuid().toString()));
            attributes.add(KeyExportableAttribute.definition());
            return attributes;
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

        List<KeyData> earlier = keyDataRepository.findByKeyCreationId(request.getKeyCreationId());
        if (!earlier.isEmpty()) {
            return replay(request.getKeyCreationId(), earlier, fingerprint);
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
        KeyData publicKey = key(created.getPublicKeyData().getUuid());
        KeyData privateKey = key(created.getPrivateKeyData().getUuid());
        remember(request.getKeyCreationId(), fingerprint, exportable(request.getCreateKeyAttributes()), publicKey,
                privateKey);

        return keyPair(publicKey, privateKey);
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

    @Override
    public List<ImportableKeyTypeV2Dto> importableKeyTypes(TokenProfileScopedRequestV2Dto request) {
        tokenContextService.resolve(request.getTokenAttributes());

        ImportableKeyTypeV2Dto importable = new ImportableKeyTypeV2Dto();
        importable.setKeyRequestType(KeyRequestType.KEY_PAIR);
        importable.setAlgorithms(IMPORTABLE_ALGORITHMS);
        return List.of(importable);
    }

    @Override
    public List<BaseAttribute> importKeyAttributes(ImportKeyAttributesRequestV2Dto request) {
        requireKeyPair(request.getKeyRequestType());
        tokenContextService.resolve(request.getTokenAttributes());

        // The material states the algorithm and its parameter set, so an import asks only where to keep the key.
        return List.of(KeyAttributes.buildDataKeyAlias());
    }

    @Override
    public KeyPairDataResponseV2Dto importKey(ImportKeyRequestV2Dto request) {
        requireKeyPair(request.getKeyRequestType());
        requireSynchronous(request.getExecutionMode());

        TokenContext token = tokenContextService.resolve(request.getTokenAttributes());

        // The material is opened before a repeat is looked for, because the key itself is part of what makes two
        // imports the same request. The platform protects the material afresh every time, so the envelope bytes say
        // nothing, and the key's public half is what identifies it. It also means a repeat carrying the wrong
        // passphrase is not answered as though it had succeeded.
        ImportedKeyMaterial material = ImportedKeyMaterial
                .open(request.getMaterial().getEncryptedPrivateKeyInfo(), request.getPassphrase());
        requireImportable(material.algorithm());

        String fingerprint = RequestFingerprint
                .of(request.getKeyRequestType(), request.getExecutionMode(), token.instance().getUuid(),
                        request.getKeyReference(), request.getTokenProfileAttributes(), request.getKeyUsages(),
                        request.getImportKeyAttributes(), request.getExportable(), material.algorithm(),
                        material.keyPair().getPublic().getEncoded());

        List<KeyData> earlier = keyDataRepository.findByKeyImportId(request.getKeyImportId());
        if (!earlier.isEmpty()) {
            return replayImport(request.getKeyImportId(), earlier, fingerprint);
        }
        requireReferenceUnclaimed(request);

        KeyPairDataResponseDto imported;
        try {
            imported = keyManagementService
                    .storeImportedKeyPair(token.instance().getUuid(), alias(request.getImportKeyAttributes()),
                            material);
        } catch (NotFoundException e) {
            throw new ResourceMissingException("The addressed token does not exist", e);
        }

        KeyData publicKey = key(imported.getPublicKeyData().getUuid());
        KeyData privateKey = key(imported.getPrivateKeyData().getUuid());
        rememberImport(request, fingerprint, publicKey, privateKey);

        return keyPair(publicKey, privateKey);
    }

    @Override
    public KeyPairOperationStatusResponseV2Dto importResult(ImportKeyResultRequestV2Dto request) {
        TokenContext token = tokenContextService.resolve(request.getTokenAttributes());

        // The identifier is looked up across every token, since it is the platform's own and one of them holds it.
        // What is answered is scoped to the token the caller opened: proving the code of one token says nothing about
        // a key in another, and an import identifier is a value a caller could otherwise guess its way to.
        List<KeyData> imported = keyDataRepository
                .findByKeyImportId(request.getKeyImportId())
                .stream()
                .filter(key -> token.instance().getUuid().equals(key.getTokenInstanceUuid()))
                .toList();
        if (imported.isEmpty()) {
            throw new ResourceMissingException("No key was imported under " + request.getKeyImportId());
        }

        KeyPairOperationStatusResponseV2Dto status = new KeyPairOperationStatusResponseV2Dto();
        status.setStatus(OperationStatus.COMPLETED);
        status
                .setResult(keyPair(half(imported, KeyType.PUBLIC_KEY, request.getKeyImportId()),
                        half(imported, KeyType.PRIVATE_KEY, request.getKeyImportId())));
        return status;
    }

    /** Answers a repeated import with the key its first attempt made, or refuses a different one wearing its id. */
    private KeyPairDataResponseV2Dto replayImport(String importId, List<KeyData> earlier, String fingerprint) {
        if (!fingerprint.equals(earlier.get(0).getImportFingerprint())) {
            throw new OperationConflictException("Key import " + importId + " already identifies a different request");
        }
        logger.debug("Answering a repeated key import {} with the key it made", importId);
        return keyPair(half(earlier, KeyType.PUBLIC_KEY, importId), half(earlier, KeyType.PRIVATE_KEY, importId));
    }

    /**
     * Writes onto the key what it was imported by. The platform addresses the key by the reference it supplied and
     * never reads it back from a response, so the binding from that reference to this key is what lets it be found
     * again.
     */
    private void rememberImport(ImportKeyRequestV2Dto request, String fingerprint, KeyData publicKey,
            KeyData privateKey) {
        for (KeyData half : List.of(publicKey, privateKey)) {
            half.setKeyImportId(request.getKeyImportId());
            half.setImportFingerprint(fingerprint);
            half.setPlatformReference(UUID.fromString(request.getKeyReference()));
            half.setExportable(request.getExportable());
        }
        try {
            keyDataRepository.saveAllAndFlush(List.of(publicKey, privateKey));
        } catch (DataIntegrityViolationException e) {
            throw new ConcurrentRequestException(
                    "Key import " + request.getKeyImportId() + " is being recorded by another request", e);
        }
    }

    private static String alias(List<RequestAttribute> importKeyAttributes) {
        StringAttributeContentV2 content = AttributeDefinitionUtils
                .getSingleItemAttributeContentValue(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS, importKeyAttributes,
                        StringAttributeContentV2.class);
        if (content == null || content.getData() == null) {
            throw new KeyManagementException("The import does not say what to call the key in the token");
        }
        return content.getData();
    }

    /**
     * The identity the platform holds for a key belongs to one key. A second import claiming it is not the repeat of an
     * earlier one, since the identifier it came under found nothing, so it is refused as a conflict: no amount of
     * repeating would free the identity.
     */
    private void requireReferenceUnclaimed(ImportKeyRequestV2Dto request) {
        UUID reference = UUID.fromString(request.getKeyReference());
        if (!keyDataRepository.findByPlatformReference(reference).isEmpty()) {
            throw new OperationConflictException(
                    "The platform already holds the reference " + reference + " for another key");
        }
    }

    /**
     * Whether a creation asked for a key that may leave the token. The contract reserves the attribute and states how
     * it is read, so the reading is the interfaces' own: a request that lost the attribute asks for a key that stays,
     * and content that cannot be read as an intent either way is refused rather than guessed at.
     */
    private static boolean exportable(List<RequestAttribute> createKeyAttributes) {
        try {
            return KeyExportableAttribute.isRequested(createKeyAttributes);
        } catch (IllegalArgumentException e) {
            throw new ValidationException(
                    ValidationError.create("The exportable intent must be stated once, as a single boolean value"));
        }
    }

    /** An algorithm the material holds that this connector does not accept as an import. */
    private static void requireImportable(KeyAlgorithm algorithm) {
        if (!IMPORTABLE_ALGORITHMS.contains(algorithm)) {
            throw new KeyTypeNotImportableException(
                    "A " + algorithm.getCode() + " key cannot be imported into this token");
        }
    }

    @Override
    public List<ExportableKeyTypeV2Dto> exportableKeyTypes(TokenProfileScopedRequestV2Dto request) {
        tokenContextService.resolve(request.getTokenAttributes());

        ExportableKeyTypeV2Dto exportable = new ExportableKeyTypeV2Dto();
        exportable.setKeyRequestType(KeyRequestType.KEY_PAIR);
        exportable.setAlgorithms(IMPORTABLE_ALGORITHMS);
        return List.of(exportable);
    }

    @Override
    public List<BaseAttribute> exportKeyAttributes(KeyScopedRequestV2Dto request) {
        keyContextService.resolve(request.getTokenAttributes(), request.getKeyMeta());

        // The request already carries the key and the passphrase, and an attribute may carry neither, so an export
        // has nothing left to ask for.
        return List.of();
    }

    @Override
    public ExportKeyResponseV2Dto exportKey(ExportKeyRequestV2Dto request) {
        return connectorMetrics.counting(ConnectorEvent.KEY_EXPORTED, () -> export(request));
    }

    private ExportKeyResponseV2Dto export(ExportKeyRequestV2Dto request) {
        requireKeyPair(request.getKeyRequestType());

        KeyContext addressed = keyContextService.resolve(request.getTokenAttributes(), request.getKeyMeta());
        List<KeyData> pair = keyDataRepository
                .findByNameAndTokenInstanceUuid(addressed.key().getName(), addressed.token().instance().getUuid());

        KeyData privateKey = half(pair, KeyType.PRIVATE_KEY, addressed.key().getName());
        KeyData publicKey = half(pair, KeyType.PUBLIC_KEY, addressed.key().getName());

        requireExportableAlgorithm(privateKey.getAlgorithm());
        requireKeyMayLeave(privateKey);
        String reference = echoedReference(request.getKeyReference(), privateKey);

        ExportKeyResponseV2Dto response = new ExportKeyResponseV2Dto();
        response.setMaterial(protect(addressed.token(), privateKey, request.getPassphrase()));
        response.setKeyReference(reference);
        response.setKeyData(publicKeyData(publicKey).getKeyData());
        return response;
    }

    /** The key itself, taken out of the token's keystore and protected under the passphrase the request carried. */
    private EncryptedKeyMaterialV2Dto protect(TokenContext token, KeyData privateKey, String passphrase) {
        KeyStore keyStore = KeyStoreUtil.loadKeystore(token.instance().getData(), token.code());
        try {
            Key stored = keyStore.getKey(privateKey.getName(), token.code().toCharArray());
            if (!(stored instanceof PrivateKey key)) {
                throw new KeyManagementException("The token holds no private key under " + privateKey.getName());
            }
            EncryptedKeyMaterialV2Dto material = new EncryptedKeyMaterialV2Dto();
            material.setEncryptedPrivateKeyInfo(ExportedKeyMaterial.protect(key, passphrase));
            return material;
        } catch (GeneralSecurityException e) {
            throw new KeyManagementException("The key could not be read out of the token");
        }
    }

    /** An algorithm this connector does not let out, which the contract names apart from the key's own permission. */
    private static void requireExportableAlgorithm(KeyAlgorithm algorithm) {
        if (!IMPORTABLE_ALGORITHMS.contains(algorithm)) {
            throw new KeyTypeNotExportableException(
                    "A " + algorithm.getCode() + " key cannot be exported from this token");
        }
    }

    /**
     * Whether the key was allowed out when it was made. The permission is set once and never raised, so a key that did
     * not carry it cannot be given it now.
     */
    private static void requireKeyMayLeave(KeyData privateKey) {
        if (!privateKey.isExportable()) {
            throw new KeyNotExportableException(
                    "The key " + privateKey.getName() + " was not made exportable and cannot leave the token");
        }
    }

    /**
     * The identity the platform holds for the key, read off the key rather than taken from the request, which is what
     * lets the platform confirm the material belongs to the key it asked about. A request naming an identity the key
     * does not carry is asking about another key.
     */
    private static String echoedReference(String stated, KeyData privateKey) {
        if (stated == null) {
            return null;
        }
        UUID held = privateKey.getPlatformReference();
        if (held == null || !held.equals(UUID.fromString(stated))) {
            throw new KeyMaterialMismatchException(
                    "The key " + privateKey.getName() + " is not the key that identity belongs to");
        }
        return held.toString();
    }

    /**
     * Answers a repeated request with the key its first attempt made, or refuses a different request wearing its id.
     * Both halves of a pair carry the identifier, and both were written together, so either states the terms.
     */
    private KeyPairDataResponseV2Dto replay(String creationId, List<KeyData> earlier, String fingerprint) {
        if (!fingerprint.equals(earlier.get(0).getCreationFingerprint())) {
            throw new OperationConflictException(
                    "Key creation " + creationId + " already identifies a different request");
        }
        logger.debug("Answering a repeated key creation {} with the key it made", creationId);
        return keyPair(half(earlier, KeyType.PUBLIC_KEY, creationId), half(earlier, KeyType.PRIVATE_KEY, creationId));
    }

    private static KeyData half(List<KeyData> pair, KeyType type, String creationId) {
        return pair
                .stream()
                .filter(key -> key.getType() == type)
                .findFirst()
                .orElseThrow(() -> new KeyManagementException(
                        "Key creation " + creationId + " is missing the " + type.getCode() + " it made"));
    }

    /**
     * Writes onto the key what it was created by, so a caller repeating the request is answered with this key rather
     * than a second one. Losing a race on the identifier means another request is writing the same creation, so this
     * attempt is rolled back and the caller repeating it is answered with the key that one made.
     */
    private void remember(String creationId, String fingerprint, boolean exportable, KeyData publicKey,
            KeyData privateKey) {
        for (KeyData half : List.of(publicKey, privateKey)) {
            half.setKeyCreationId(creationId);
            half.setCreationFingerprint(fingerprint);
            half.setExportable(exportable);
        }
        try {
            keyDataRepository.saveAllAndFlush(List.of(publicKey, privateKey));
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
    public void setConnectorMetrics(ConnectorMetrics connectorMetrics) {
        this.connectorMetrics = connectorMetrics;
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
