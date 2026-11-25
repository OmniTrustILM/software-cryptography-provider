package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.common.v2.OperationStatus;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.value.CustomKeyValue;
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
import com.otilm.api.model.connector.cryptography.v2.key.KeyEntryStatus;
import com.otilm.api.model.connector.cryptography.v2.key.KeyEntryV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyExportableAttribute;
import com.otilm.api.model.connector.cryptography.v2.key.KeyHandleV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairOperationStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyResolutionV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListKeysRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListKeysResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListedKeyEntryV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListedKeyPairV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ResolveKeysRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ResolveKeysResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.material.EncryptedKeyMaterialV2Dto;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.attribute.KeySpecV2Attributes;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.dao.repository.KeyDataRepository;
import com.otilm.cp.soft.exception.ConcurrentRequestException;
import com.otilm.cp.soft.exception.KeyManagementException;
import com.otilm.cp.soft.exception.KeyMaterialMismatchException;
import com.otilm.cp.soft.exception.KeyNotExportableException;
import com.otilm.cp.soft.exception.KeyTypeNotExportableException;
import com.otilm.cp.soft.exception.KeyTypeNotImportableException;
import com.otilm.cp.soft.exception.KeyTypeNotListableException;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.OperationConflictException;
import com.otilm.cp.soft.exception.OperationNotTrackedException;
import com.otilm.cp.soft.exception.ParameterUnsupportedException;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.metrics.ConnectorEvent;
import com.otilm.cp.soft.metrics.ConnectorMetrics;
import com.otilm.cp.soft.model.KeyContext;
import com.otilm.cp.soft.model.TokenContext;
import com.otilm.cp.soft.service.CryptographicKeyV2Service;
import com.otilm.cp.soft.service.KeyContextService;
import com.otilm.cp.soft.service.KeyManagementService;
import com.otilm.cp.soft.service.TokenContextService;
import com.otilm.cp.soft.util.AttributeValue;
import com.otilm.cp.soft.util.ExportedKeyMaterial;
import com.otilm.cp.soft.util.ImportedKeyMaterial;
import com.otilm.cp.soft.util.KeyStoreUtil;
import com.otilm.cp.soft.util.PrivateKeyDescriptor;
import com.otilm.cp.soft.util.RequestFingerprint;
import com.otilm.cp.soft.util.SignatureAlgorithms;
import jakarta.transaction.Transactional;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.Strings;
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

    private static final Set<KeyAlgorithm> POST_QUANTUM_SIGNATURE_ALGORITHMS = Set
            .of(KeyAlgorithm.FALCON, KeyAlgorithm.MLDSA, KeyAlgorithm.SLHDSA);

    private ConnectorMetrics connectorMetrics;

    private KeyContextService keyContextService;

    private KeyDataRepository keyDataRepository;

    private KeyManagementService keyManagementService;

    private TokenContextService tokenContextService;

    @Override
    public List<BaseAttribute> createKeyAttributes(CreateKeyAttributesRequestV2Dto request) {
        requireKeyPair(request.getKeyRequestType());
        tokenContextService.locate(request.getTokenAttributes());

        // V1's key specification offers keys V2 cannot sign with, so V2 asks for its own. The exportable intent is V2's
        // alone, since a v1 caller neither states it nor is answered by anything that reads it.
        return List
                .of(KeyAttributes.buildOptionalDataKeyAlias(), KeyAttributes.buildDataKeyAlgorithmSelect(),
                        KeySpecV2Attributes.buildGroup(), KeyExportableAttribute.definition());
    }

    @Override
    public KeyPairDataResponseV2Dto createKey(CreateKeyRequestV2Dto request) {
        requireKeyPair(request.getKeyRequestType());
        requireSynchronous(request.getExecutionMode());

        TokenContext token = tokenContextService.resolve(request.getTokenAttributes());
        // The resolved token stands for the context the request carried. The context itself carries the code that
        // opens the token, and the fingerprint is stored, so what identifies the token is fingerprinted instead.
        // Token-profile key usages are Core policy; changing them preserves the key-creation replay identity.
        String fingerprint = RequestFingerprint
                .of(request.getKeyRequestType(), request.getExecutionMode(), token.instance().getUuid(),
                        request.getTokenProfileAttributes(), request.getCreateKeyAttributes());

        List<KeyData> earlier = keyDataRepository.findByKeyCreationId(request.getKeyCreationId());
        if (!earlier.isEmpty()) {
            return replay(request.getKeyCreationId(), earlier, fingerprint);
        }

        CreateKeyRequestDto creation = new CreateKeyRequestDto();
        creation.setTokenProfileAttributes(request.getTokenProfileAttributes());
        creation
                .setCreateKeyAttributes(
                        withAlias(withFixedParameters(request.getCreateKeyAttributes()), request.getKeyCreationId()));

        KeyPairDataResponseDto created;
        try {
            created = keyManagementService.createKeyPair(token.instance().getUuid(), creation);
        } catch (NotFoundException e) {
            throw new ResourceMissingException("The addressed token does not exist", e);
        }
        KeyData publicKey = key(created.getPublicKeyData().getUuid());
        KeyData privateKey = key(created.getPrivateKeyData().getUuid());
        if (signsUnderNoPlatformAlgorithm(privateKey.getAlgorithm(),
                ((CustomKeyValue) privateKey.getValue()).getValues())) {
            // Refused after the key is made, so it is the shared creation that decides which parameter set was asked
            // for; the transaction takes the key back with it.
            throw new ParameterUnsupportedException(
                    "V2 creates a signing key only in a parameter set a platform signature algorithm names");
        }
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
        tokenContextService.locate(request.getTokenAttributes());

        ImportableKeyTypeV2Dto importable = new ImportableKeyTypeV2Dto();
        importable.setKeyRequestType(KeyRequestType.KEY_PAIR);
        importable.setAlgorithms(IMPORTABLE_ALGORITHMS);
        return List.of(importable);
    }

    @Override
    public List<BaseAttribute> importKeyAttributes(ImportKeyAttributesRequestV2Dto request) {
        requireImportableKeyPair(request.getKeyRequestType());
        tokenContextService.locate(request.getTokenAttributes());

        // The material states the algorithm and its parameter set, so an import asks only where to keep the key.
        return List.of(KeyAttributes.buildOptionalDataKeyAlias());
    }

    @Override
    public KeyPairDataResponseV2Dto importKey(ImportKeyRequestV2Dto request) {
        requireImportableKeyPair(request.getKeyRequestType());
        requireSynchronous(request.getExecutionMode());

        TokenContext token = tokenContextService.resolve(request.getTokenAttributes());

        // The material is opened before a repeat is looked for, because the key itself is part of what makes two
        // imports the same request. The platform protects the material afresh every time, so the envelope bytes say
        // nothing, and the key's public half is what identifies it. It also means a repeat carrying the wrong
        // passphrase is not answered as though it had succeeded.
        ImportedKeyMaterial material = ImportedKeyMaterial
                .open(request.getMaterial().getEncryptedPrivateKeyInfo(), request.getPassphrase());
        requireImportable(material.algorithm());
        if (signsUnderNoPlatformAlgorithm(material.algorithm(),
                PrivateKeyDescriptor.of(material.algorithm(), material.keyPair()).getValues())) {
            throw new KeyTypeNotImportableException(
                    "A key whose parameter set no platform signature algorithm names cannot be imported");
        }

        // Token-profile key usages are Core policy; changing them preserves the key-import replay identity.
        String fingerprint = RequestFingerprint
                .of(request.getKeyRequestType(), request.getExecutionMode(), token.instance().getUuid(),
                        request.getKeyReference(), request.getTokenProfileAttributes(),
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
                    .storeImportedKeyPair(token.instance().getUuid(),
                            alias(request.getImportKeyAttributes(), request.getKeyImportId()), material);
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
        // The identifier is looked up across every token, since it is the platform's own and one of them holds it.
        // What is answered is scoped to the token the caller opened: proving the code of one token says nothing about
        // a key in another, and an import identifier is a value a caller could otherwise guess its way to. A token
        // that does not exist holds no key, so there is nothing to bring into existence to answer this.
        List<KeyData> imported = tokenContextService
                .locate(request.getTokenAttributes())
                .map(token -> keyDataRepository
                        .findByKeyImportId(request.getKeyImportId())
                        .stream()
                        .filter(key -> token.instance().getUuid().equals(key.getTokenInstanceUuid()))
                        .toList())
                .orElse(List.of());
        if (imported.isEmpty()) {
            throw new OperationNotTrackedException("No key was imported under " + request.getKeyImportId());
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
            half.setPlatformReference(reference(request.getKeyReference()));
            half.setExportable(request.getExportable());
        }
        try {
            keyDataRepository.saveAllAndFlush(List.of(publicKey, privateKey));
        } catch (DataIntegrityViolationException e) {
            throw new ConcurrentRequestException(
                    "Key import " + request.getKeyImportId() + " is being recorded by another request", e);
        }
    }

    /**
     * The alias a request states, or one derived from the identifier of the operation when it states none. The platform
     * sends a fresh identifier for every creation and import, so each key gets its own, and a repeat of the same
     * operation names the same key.
     */
    private static String alias(List<RequestAttribute> attributes, String operationId) {
        String alias = AttributeValue.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS, attributes);
        return alias == null || alias.isBlank()
                ? UUID.nameUUIDFromBytes(operationId.getBytes(StandardCharsets.UTF_8)).toString()
                : alias;
    }

    /**
     * The identity the platform holds for a key belongs to one key. A second import claiming it is not the repeat of an
     * earlier one, since the identifier it came under found nothing, so it is refused as a conflict: no amount of
     * repeating would free the identity.
     */
    private void requireReferenceUnclaimed(ImportKeyRequestV2Dto request) {
        UUID reference = reference(request.getKeyReference());
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

    /** The attributes with the alias {@link #alias} settles on in place of whatever the request stated for it. */
    private static List<RequestAttribute> withAlias(List<RequestAttribute> attributes, String keyCreationId) {
        List<RequestAttribute> named = new ArrayList<>(attributes);
        named.removeIf(attribute -> KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS.equals(attribute.getName()));
        RequestAttributeV2 alias = new RequestAttributeV2();
        alias.setName(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS);
        alias.setContent(List.of(new StringAttributeContentV2(alias(attributes, keyCreationId))));
        named.add(alias);
        return named;
    }

    /**
     * A creation states nothing for the choices V2 leaves out of its key specification, so it is given the one value V2
     * offers there. What it does state is left for the shared creation to read.
     */
    private static List<RequestAttribute> withFixedParameters(List<RequestAttribute> attributes) {
        String algorithm = attributes == null
                ? null
                : AttributeValue.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, attributes);
        if (algorithm == null) {
            return attributes;
        }
        List<RequestAttribute> stated = new ArrayList<>(attributes);
        KeySpecV2Attributes
                .fixedParameters(KeyAlgorithm.findByCode(algorithm))
                .stream()
                .filter(fixed -> attributes
                        .stream()
                        .noneMatch(attribute -> fixed.getName().equals(attribute.getName())))
                .forEach(stated::add);
        return stated;
    }

    /** V2 names every signature by a platform algorithm, and only a post-quantum signing key can lack one. */
    private static boolean signsUnderNoPlatformAlgorithm(KeyAlgorithm algorithm, Map<String, String> parameters) {
        return POST_QUANTUM_SIGNATURE_ALGORITHMS.contains(algorithm)
                && SignatureAlgorithms.ofPostQuantumKey(algorithm, parameters).isEmpty();
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
        tokenContextService.locate(request.getTokenAttributes());

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
        requireExportableKeyPair(request.getKeyRequestType());
        return connectorMetrics.counting(ConnectorEvent.KEY_EXPORTED, () -> export(request));
    }

    private ExportKeyResponseV2Dto export(ExportKeyRequestV2Dto request) {
        KeyContext addressed = keyContextService.resolve(request.getTokenAttributes(), request.getKeyMeta());
        List<KeyData> pair = keyDataRepository
                .findByNameAndTokenInstanceUuid(addressed.key().getName(), addressed.token().instance().getUuid());

        KeyData privateKey = half(pair, KeyType.PRIVATE_KEY, addressed.key().getName());
        KeyData publicKey = half(pair, KeyType.PUBLIC_KEY, addressed.key().getName());

        requireExportableAlgorithm(privateKey.getAlgorithm());
        requireKeyMayLeave(privateKey);
        String reference = echoedReference(request.getKeyReference(), privateKey);

        ExportKeyResponseV2Dto response = new ExportKeyResponseV2Dto();
        response.setMaterial(protect(addressed.token(), privateKey, publicKey, request.getPassphrase()));
        response.setKeyReference(reference);
        response.setKeyData(publicKeyData(publicKey).getKeyData());
        return response;
    }

    /**
     * Refuses to hand out a key that is not the one the row asked for. A keystore tells two aliases apart without
     * regard to case, so a token written before that was enforced can hold one key under two rows; what it holds is
     * then not what either row describes, and handing it out would give away a key the request never named — one whose
     * own row may say it must never leave. The certificate stored beside the key states its public half, so the two are
     * compared before anything is protected.
     */
    private static void requireTheKeyTheRowDescribes(KeyStore keyStore, KeyData privateKey, KeyData publicKey)
            throws KeyStoreException {
        Certificate held = keyStore.getCertificate(privateKey.getName());
        byte[] described = spki(publicKey);
        if (held == null || described == null || !Arrays.equals(held.getPublicKey().getEncoded(), described)) {
            throw new KeyManagementException(
                    "The token holds a key under " + privateKey.getName() + " that this key does not describe");
        }
    }

    /** The key itself, taken out of the token's keystore and protected under the passphrase the request carried. */
    private EncryptedKeyMaterialV2Dto protect(TokenContext token, KeyData privateKey, KeyData publicKey,
            String passphrase) {
        KeyStore keyStore = KeyStoreUtil.loadKeystore(token.instance().getData(), token.code());
        try {
            Key stored = keyStore.getKey(privateKey.getName(), token.code().toCharArray());
            if (!(stored instanceof PrivateKey key)) {
                throw new KeyManagementException("The token holds no private key under " + privateKey.getName());
            }
            requireTheKeyTheRowDescribes(keyStore, privateKey, publicKey);
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
        if (held == null || !held.equals(reference(stated))) {
            throw new KeyMaterialMismatchException(
                    "The key " + privateKey.getName() + " is not the key that identity belongs to");
        }
        return stated;
    }

    /**
     * The identity a request states, as the value it stands for. The contract requires it to be written as a UUID and a
     * request is held to that before it arrives here, so this is what a request reaching here another way is held to:
     * an identity that is not one of these belongs to no key this provider issued.
     */
    private static UUID reference(String stated) {
        try {
            return UUID.fromString(stated);
        } catch (IllegalArgumentException e) {
            throw new KeyMaterialMismatchException("The stated identity is not one this provider issued");
        }
    }

    @Override
    public ListKeysResponseV2Dto listKeys(ListKeysRequestV2Dto request) {
        requireListableKeyPair(request.getKeyRequestType());
        TokenKeys keys = tokenKeys(request.getTokenAttributes());

        ListKeysResponseV2Dto response = new ListKeysResponseV2Dto();
        response
                .setItems(keys
                        .privateKeys()
                        .stream()
                        .skip(request.getOffset())
                        .limit(request.getLimit())
                        .map(key -> admit(key, keys, new ListedKeyEntryV2Dto()))
                        .toList());
        response.setTotalItems((long) keys.privateKeys().size());
        return response;
    }

    @Override
    public ResolveKeysResponseV2Dto resolveKeys(ResolveKeysRequestV2Dto request) {
        requireListableKeyPair(request.getKeyRequestType());
        TokenKeys keys = tokenKeys(request.getTokenAttributes());
        return new ResolveKeysResponseV2Dto(request.getKeys().stream().map(handle -> resolve(handle, keys)).toList());
    }

    /** A token no request has used yet holds no keys. */
    private TokenKeys tokenKeys(List<RequestAttribute> tokenAttributes) {
        return tokenContextService
                .locate(tokenAttributes)
                .map(token -> TokenKeys
                        .of(keyDataRepository.findAllByTokenInstanceUuid(token.instance().getUuid()), token))
                .orElseGet(() -> TokenKeys.of(List.of(), null));
    }

    private KeyResolutionV2Dto resolve(KeyHandleV2Dto handle, TokenKeys keys) {
        KeyResolutionV2Dto resolution = new KeyResolutionV2Dto();
        resolution.setIdentifier(handle.getIdentifier());
        Optional<String> alias = issuedAlias(handle.getKeyMeta());
        if (alias.isEmpty()) {
            return blocked(resolution, KeyEntryStatus.INVALID_HANDLE,
                    "The handle is not the single key alias this connector issues.");
        }
        return keys
                .privateKeyNamed(alias.get())
                .map(key -> admit(key, keys, resolution))
                .orElseGet(() -> blocked(resolution, KeyEntryStatus.NOT_FOUND,
                        "The token holds no private key under the alias the handle names."));
    }

    /** The alias a handle names when it has the shape {@link KeyContextService#publishPair} issues. */
    private static Optional<String> issuedAlias(List<MetadataAttribute> handle) {
        if (handle.size() != 1) {
            return Optional.empty();
        }
        MetadataAttribute attribute = handle.get(0);
        boolean namesAnAlias = KeyAttributes.ATTRIBUTE_META_KEY_ALIAS.equals(attribute.getName())
                && attribute.getContentType() == AttributeContentType.STRING;
        return namesAnAlias && soleData(attribute) instanceof String alias ? Optional.of(alias) : Optional.empty();
    }

    private static Object soleData(MetadataAttribute attribute) {
        List<? extends AttributeContent> content = attribute.getContent();
        return content != null && content.size() == 1 && content.get(0) != null ? content.get(0).getData() : null;
    }

    /**
     * Reports the connector's status for the pair, which Core weighs when it decides admission. Only an available pair
     * carries the key, described as its creation describes it.
     */
    private <T extends KeyEntryV2Dto> T admit(KeyData privateKey, TokenKeys keys, T entry) {
        entry.setStorageName(privateKey.getName());
        if (keys.sharesAlias(privateKey)) {
            return withheld(entry, KeyEntryStatus.UNADDRESSABLE,
                    "Several private keys in the token share this alias, which the keystore reads without regard to "
                            + "case, so it addresses none of them.",
                    privateKey, keys);
        }
        try {
            if (!heldByTheKeystore(privateKey, keys)) {
                return withheld(entry, KeyEntryStatus.UNREADABLE, "The token holds no key under this alias.",
                        privateKey, keys);
            }
            if (signsUnderNoPlatformAlgorithm(privateKey)) {
                return withheld(entry, KeyEntryStatus.UNSUPPORTED_TYPE,
                        "No platform signature algorithm names the parameter set of the key.", privateKey, keys);
            }
            entry.setKey(listedPair(privateKey, keys));
        } catch (UnreadableKeyException e) {
            logger.debug("The key rows of the pair {} cannot be read", privateKey.getUuid(), e);
            return withheld(entry, KeyEntryStatus.UNREADABLE, e.getMessage(), privateKey, keys);
        }
        entry.setStatus(KeyEntryStatus.AVAILABLE);
        return entry;
    }

    /** A pair whose public half was destroyed on its own is listed without it. */
    private ListedKeyPairV2Dto listedPair(KeyData privateKey, TokenKeys keys) {
        ListedKeyPairV2Dto pair = new ListedKeyPairV2Dto();
        pair.setKeyPairMeta(keyContextService.publishPair(privateKey));
        KeyData publicKey = keys.publicHalfOf(privateKey);
        try {
            if (publicKey != null) {
                pair.setPublicKeyData(publicKeyData(publicKey));
            }
            pair.setPrivateKeyData(privateKeyResponse(privateKey, algorithmIdentifierOf(privateKey, keys)));
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new UnreadableKeyException("The public key stored for the pair cannot be read.", e);
        }
        return pair;
    }

    private static final String UNREADABLE_PARAMETERS = "The parameters stored for the private key cannot be read.";

    private static final class UnreadableKeyException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        UnreadableKeyException(String diagnostic, RuntimeException cause) {
            super(diagnostic, cause);
        }
    }

    private static boolean heldByTheKeystore(KeyData privateKey, TokenKeys keys) {
        try {
            return keys.holdsKeyUnder(privateKey);
        } catch (IllegalStateException e) {
            throw new UnreadableKeyException("The keystore of the token cannot be read.", e);
        }
    }

    private static boolean signsUnderNoPlatformAlgorithm(KeyData privateKey) {
        try {
            if (privateKey.getValue() instanceof CustomKeyValue value) {
                return signsUnderNoPlatformAlgorithm(privateKey.getAlgorithm(), value.getValues());
            }
        } catch (RuntimeException e) {
            throw new UnreadableKeyException(UNREADABLE_PARAMETERS, e);
        }
        throw new UnreadableKeyException(UNREADABLE_PARAMETERS, null);
    }

    /** A blocked key still carries the private-key descriptor Core displays. */
    private static <T extends KeyEntryV2Dto> T withheld(T entry, KeyEntryStatus status, String diagnostic,
            KeyData privateKey, TokenKeys keys) {
        entry.setKeyData(withheldKeyDescriptor(privateKey, keys));
        return blocked(entry, status, diagnostic);
    }

    /** Names the key's parameters where they can still be read. */
    private static PrivateKeyDataV2Dto withheldKeyDescriptor(KeyData privateKey, TokenKeys keys) {
        try {
            return privateKeyDescriptor(privateKey, algorithmIdentifierOf(privateKey, keys));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return privateKeyDescriptor(privateKey, null);
        }
    }

    private static <T extends KeyEntryV2Dto> T blocked(T entry, KeyEntryStatus status, String diagnostic) {
        entry.setStatus(status);
        entry.setDiagnostic(diagnostic);
        return entry;
    }

    /**
     * The AlgorithmIdentifier of a private key, read from its public row or, once that row is gone, from the
     * certificate the keystore keeps beside the key.
     */
    private static byte[] algorithmIdentifierOf(KeyData privateKey, TokenKeys keys) {
        KeyData publicKey = keys.publicHalfOf(privateKey);
        if (publicKey != null) {
            return algorithmIdentifierOf(spki(publicKey));
        }
        Certificate certificate = keys.certificateOf(privateKey);
        return certificate == null ? null : algorithmIdentifierOf(certificate.getPublicKey().getEncoded());
    }

    /**
     * The key rows of one token, with the private halves sorted by alias and then by row UUID. Aliases are folded as
     * the PKCS#12 keystore folds them, since that is how it looks a key up.
     */
    private static final class TokenKeys {

        private final List<KeyData> privateKeys;

        private final Map<String, List<KeyData>> privateKeysByAlias;

        private final Map<String, KeyData> publicKeysByAssociation;

        private final TokenContext token;

        private KeyStore keyStore;

        private TokenKeys(List<KeyData> privateKeys, Map<String, KeyData> publicKeysByAssociation, TokenContext token) {
            this.privateKeys = privateKeys;
            this.privateKeysByAlias = privateKeys.stream().collect(Collectors.groupingBy(key -> folded(key.getName())));
            this.publicKeysByAssociation = publicKeysByAssociation;
            this.token = token;
        }

        static TokenKeys of(List<KeyData> rows, TokenContext token) {
            List<KeyData> privateKeys = rows
                    .stream()
                    .filter(key -> key.getType() == KeyType.PRIVATE_KEY)
                    .sorted(Comparator
                            .comparing(KeyData::getName, String.CASE_INSENSITIVE_ORDER)
                            .thenComparing(KeyData::getUuid))
                    .toList();
            Map<String, KeyData> publicKeysByAssociation = rows
                    .stream()
                    .filter(key -> key.getType() == KeyType.PUBLIC_KEY && key.getAssociation() != null)
                    .collect(Collectors.toMap(KeyData::getAssociation, Function.identity(), (first, later) -> first));
            return new TokenKeys(privateKeys, publicKeysByAssociation, token);
        }

        List<KeyData> privateKeys() {
            return privateKeys;
        }

        /**
         * Creation refuses an alias the token holds in another case. Only rows stored before that rule share an alias.
         */
        boolean sharesAlias(KeyData privateKey) {
            return privateKeysByAlias.getOrDefault(folded(privateKey.getName()), List.of()).size() > 1;
        }

        Optional<KeyData> privateKeyNamed(String alias) {
            return privateKeysByAlias.getOrDefault(folded(alias), List.of()).stream().findFirst();
        }

        KeyData publicHalfOf(KeyData privateKey) {
            return publicKeysByAssociation.get(privateKey.getAssociation());
        }

        /** A pair that shared its keystore entry with another loses it when that pair is destroyed. */
        boolean holdsKeyUnder(KeyData privateKey) {
            try {
                return keyStore().isKeyEntry(privateKey.getName());
            } catch (KeyStoreException e) {
                throw new IllegalStateException("The keystore of the token cannot be read", e);
            }
        }

        /** Only an alias of its own addresses one certificate. */
        Certificate certificateOf(KeyData privateKey) {
            if (sharesAlias(privateKey)) {
                return null;
            }
            try {
                return keyStore().getCertificate(privateKey.getName());
            } catch (KeyStoreException e) {
                throw new IllegalStateException("The keystore of the token cannot be read", e);
            }
        }

        /** The keystore is opened once a pair needs it. */
        private KeyStore keyStore() {
            if (keyStore == null) {
                keyStore = KeyStoreUtil.loadKeystore(token.instance().getData(), token.code());
            }
            return keyStore;
        }

        private static String folded(String alias) {
            return Strings.toLowerCase(alias);
        }
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

    /**
     * One half of a key pair. Each half is a key in its own right and can be destroyed on its own, so what an
     * identifier finds may no longer be a whole pair: the key is gone rather than the request being wrong, and no
     * amount of repeating the request would bring it back.
     */
    private static KeyData half(List<KeyData> pair, KeyType type, String describedBy) {
        return pair
                .stream()
                .filter(key -> key.getType() == type)
                .findFirst()
                .orElseThrow(() -> new ResourceMissingException(
                        "The " + type.getCode() + " of the key " + describedBy + " no longer exists"));
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
        response.setKeyPairMeta(keyContextService.publishPair(privateKey));
        response.setPublicKeyData(publicKeyData(publicKey));
        response.setPrivateKeyData(privateKeyData(privateKey, spki(publicKey)));
        return response;
    }

    private PublicKeyDataResponseV2Dto publicKeyData(KeyData key) {
        PublicKeyDataV2Dto descriptor = new PublicKeyDataV2Dto();
        descriptor.setAlgorithm(key.getAlgorithm());
        descriptor.setPublicKeySpki(spki(key));

        PublicKeyDataResponseV2Dto response = new PublicKeyDataResponseV2Dto();
        response.setKeyMeta(keyContextService.publish(key));
        response.setKeyData(descriptor);
        return response;
    }

    private PrivateKeyDataResponseV2Dto privateKeyData(KeyData key, byte[] pairSpki) {
        return privateKeyResponse(key, algorithmIdentifierOf(pairSpki));
    }

    private PrivateKeyDataResponseV2Dto privateKeyResponse(KeyData key, byte[] algorithmIdentifier) {
        PrivateKeyDataResponseV2Dto response = new PrivateKeyDataResponseV2Dto();
        response.setKeyMeta(keyContextService.publish(key));
        response.setKeyData(privateKeyDescriptor(key, algorithmIdentifier));
        return response;
    }

    private static PrivateKeyDataV2Dto privateKeyDescriptor(KeyData key, byte[] algorithmIdentifier) {
        PrivateKeyDataV2Dto descriptor = new PrivateKeyDataV2Dto();
        descriptor.setAlgorithm(key.getAlgorithm());
        descriptor.setAlgorithmIdentifier(algorithmIdentifier);
        if (key.getAlgorithm() == KeyAlgorithm.RSA) {
            descriptor.setLength(key.getLength());
        }
        return descriptor;
    }

    /** The stored public key, whose value is the SPKI this provider recorded when the key was created. */
    private static byte[] spki(KeyData key) {
        if (key.getValue() instanceof SpkiKeyValue spki && spki.getValue() != null) {
            return Base64.getDecoder().decode(spki.getValue());
        }
        return null;
    }

    /** Reached only with an SPKI the public descriptor has already accepted, so its failure is tested directly. */
    static byte[] algorithmIdentifierOf(byte[] spki) {
        try {
            return SubjectPublicKeyInfo.getInstance(spki).getAlgorithm().getEncoded(ASN1Encoding.DER);
        } catch (IOException | RuntimeException e) {
            throw new IllegalStateException("A key this provider created has an unreadable public key", e);
        }
    }

    /** A secret key is neither taken in nor let out, which the contract names apart from an unoffered operation. */
    private static void requireImportableKeyPair(KeyRequestType keyRequestType) {
        if (keyRequestType != KeyRequestType.KEY_PAIR) {
            throw new KeyTypeNotImportableException("A secret key cannot be imported into this token");
        }
    }

    private static void requireExportableKeyPair(KeyRequestType keyRequestType) {
        if (keyRequestType != KeyRequestType.KEY_PAIR) {
            throw new KeyTypeNotExportableException("A secret key cannot be exported from this token");
        }
    }

    private static void requireListableKeyPair(KeyRequestType keyRequestType) {
        if (keyRequestType != KeyRequestType.KEY_PAIR) {
            throw new KeyTypeNotListableException("This token holds no secret keys to list");
        }
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
