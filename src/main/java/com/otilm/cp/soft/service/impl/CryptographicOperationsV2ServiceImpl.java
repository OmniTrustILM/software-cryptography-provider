package com.otilm.cp.soft.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.key.value.CustomKeyValue;
import com.otilm.api.model.connector.cryptography.key.value.SpkiKeyValue;
import com.otilm.api.model.connector.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.EncryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.RandomDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.connector.cryptography.v2.KeyScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.CipherDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.DecryptDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.RandomDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataResponseV2Dto;
import com.otilm.cp.soft.attribute.EcdsaKeyAttributes;
import com.otilm.cp.soft.attribute.OperationAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.collection.MLDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASignatureMode;
import com.otilm.cp.soft.dao.entity.KeyData;
import com.otilm.cp.soft.dao.repository.KeyDataRepository;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import com.otilm.cp.soft.exception.ParameterUnsupportedException;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.model.KeyContext;
import com.otilm.cp.soft.model.TokenContext;
import com.otilm.cp.soft.service.CryptographicOperationsService;
import com.otilm.cp.soft.service.CryptographicOperationsV2Service;
import com.otilm.cp.soft.service.KeyContextService;
import com.otilm.cp.soft.service.TokenContextService;
import com.otilm.cp.soft.util.OperationDataMapper;
import jakarta.transaction.Transactional;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * V2 operations use the keys stored for both interface versions. Key-scoped requests resolve token and key metadata,
 * and execution delegates to the shared cryptographic service.
 */
@Service
@Transactional
public class CryptographicOperationsV2ServiceImpl implements CryptographicOperationsV2Service {

    private static final int PKCS1_V1_5_PADDING_BYTES = 11;

    private static final int DIGEST_INFO_PREFIX_BYTES = 19;

    private static final int PSS_TRAILER_BYTES = 2;

    private static final List<SignatureAlgorithm> RSA_ALGORITHMS = List
            .of(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA,
                    SignatureAlgorithm.SHA512_WITH_RSA, SignatureAlgorithm.SHA256_WITH_RSA_PSS,
                    SignatureAlgorithm.SHA384_WITH_RSA_PSS, SignatureAlgorithm.SHA512_WITH_RSA_PSS);

    private CryptographicOperationsService cryptographicOperationsService;

    private KeyContextService keyContextService;

    private TokenContextService tokenContextService;

    private KeyDataRepository keyDataRepository;

    /** The addressed key determines which reserved signature algorithm choices are offered. */
    @Override
    public List<BaseAttribute> signatureAttributes(KeyScopedRequestV2Dto request) {
        return List.of(SignatureAlgorithmAttribute.definition(supportedAlgorithms(key(request).key())));
    }

    private List<SignatureAlgorithm> supportedAlgorithms(KeyData key) {
        return switch (key.getAlgorithm()) {
            case RSA -> RSA_ALGORITHMS.stream().filter(algorithm -> fitsRsaKey(algorithm, key.getLength())).toList();
            case ECDSA -> List
                    .of(SignatureAlgorithm.SHA256_WITH_ECDSA, SignatureAlgorithm.SHA384_WITH_ECDSA,
                            SignatureAlgorithm.SHA512_WITH_ECDSA);
            case FALCON, MLDSA, SLHDSA -> supportedPostQuantumAlgorithm(key);
            default -> throw new ParameterUnsupportedException("This key has no supported signature algorithm");
        };
    }

    private static boolean fitsRsaKey(SignatureAlgorithm algorithm, int modulusBits) {
        int digestBytes = switch (algorithm) {
            case SHA256_WITH_RSA, SHA256_WITH_RSA_PSS -> 32;
            case SHA384_WITH_RSA, SHA384_WITH_RSA_PSS -> 48;
            case SHA512_WITH_RSA, SHA512_WITH_RSA_PSS -> 64;
            default -> throw new IllegalArgumentException("Not an RSA signature algorithm: " + algorithm);
        };
        if (algorithm.name().endsWith("_PSS")) {
            int encodedBytes = (modulusBits + 6) / 8;
            return encodedBytes >= 2 * digestBytes + PSS_TRAILER_BYTES;
        }
        int modulusBytes = (modulusBits + 7) / 8;
        return modulusBytes >= DIGEST_INFO_PREFIX_BYTES + digestBytes + PKCS1_V1_5_PADDING_BYTES;
    }

    private List<SignatureAlgorithm> supportedPostQuantumAlgorithm(KeyData key) {
        KeyData publicKey = key.getType() == KeyType.PUBLIC_KEY
                ? key
                : keyDataRepository
                        .findByNameAndTokenInstanceUuid(key.getName(), key.getTokenInstanceUuid())
                        .stream()
                        .filter(half -> half.getType() == KeyType.PUBLIC_KEY
                                && Objects.equals(half.getAssociation(), key.getAssociation()))
                        .findFirst()
                        .orElse(null);
        if (publicKey == null) {
            return supportedPostQuantumAlgorithmFromPrivateKey(key);
        }
        try {
            SpkiKeyValue value = (SpkiKeyValue) publicKey.getValue();
            ASN1ObjectIdentifier oid = SubjectPublicKeyInfo
                    .getInstance(Base64.getDecoder().decode(value.getValue()))
                    .getAlgorithm()
                    .getAlgorithm();
            List<SignatureAlgorithm> supported = Stream
                    .of(SignatureAlgorithm.values())
                    .filter(algorithm -> oid.equals(algorithm.getAlgorithmIdentifier().getAlgorithm()))
                    .toList();
            if (supported.isEmpty()) {
                throw new ParameterUnsupportedException("This key has no supported signature algorithm");
            }
            return supported;
        } catch (IllegalArgumentException | ClassCastException e) {
            throw new CryptographicOperationException("The stored public key has invalid signature parameters");
        }
    }

    private static List<SignatureAlgorithm> supportedPostQuantumAlgorithmFromPrivateKey(KeyData key) {
        try {
            Map<String, String> values = ((CustomKeyValue) key.getValue()).getValues();
            if (key.getAlgorithm() != KeyAlgorithm.FALCON) {
                String prehash = values.get("prehash");
                if (!"true".equals(prehash) && !"false".equals(prehash)) {
                    throw new IllegalArgumentException("Missing prehash selection");
                }
                if (Boolean.parseBoolean(prehash)) {
                    throw new ParameterUnsupportedException("This key has no supported signature algorithm");
                }
            }
            String name = switch (key.getAlgorithm()) {
                case FALCON -> "FALCON_" + values.get("degree");
                case MLDSA ->
                    "ML_DSA_" + MLDSASecurityCategory.valueOf(Integer.parseInt(values.get("level"))).getParameterSet();
                case SLHDSA -> {
                    String category = Stream
                            .of(SLHDSASecurityCategory.values())
                            .filter(value -> value.getNistSecurityCategory().equals(values.get("securityCategory")))
                            .findFirst()
                            .orElseThrow()
                            .getSecurityParameterLength();
                    String mode = SLHDSASignatureMode
                            .valueOf(values.get("tradeoff"))
                            .getParameterName()
                            .toUpperCase(Locale.ROOT);
                    yield "SLH_DSA_" + values.get("hash") + "_" + category + mode;
                }
                default -> throw new IllegalArgumentException("Not a post-quantum signature key");
            };
            List<SignatureAlgorithm> supported = Stream
                    .of(SignatureAlgorithm.values())
                    .filter(algorithm -> algorithm.name().equals(name))
                    .toList();
            if (supported.isEmpty()) {
                throw new ParameterUnsupportedException("This key has no supported signature algorithm");
            }
            return supported;
        } catch (IllegalArgumentException | ClassCastException | NoSuchElementException e) {
            throw new CryptographicOperationException("The stored private key has invalid signature parameters");
        }
    }

    @Override
    public List<BaseAttribute> cipherAttributes(KeyScopedRequestV2Dto request) {
        return OperationAttributes.cipherAttributes(key(request).key().getAlgorithm());
    }

    @Override
    public List<BaseAttribute> randomAttributes(TokenProfileScopedRequestV2Dto request) {
        tokenContextService.locate(request.getTokenAttributes());
        return List.of();
    }

    @Override
    public SignDataResponseV2Dto signData(SignDataRequestV2Dto request) {
        KeyContext key = key(request);

        SignDataRequestDto signing = new SignDataRequestDto();
        signing.setSignatureAttributes(signingParameters(key.key(), request.getSignatureAttributes()));
        signing.setData(OperationDataMapper.toSignatureRequests(request.getData()));

        SignDataResponseDto signed = perform(() -> cryptographicOperationsService
                .signData(key.token().instance().getUuid(), key.key().getUuid(), signing));

        SignDataResponseV2Dto response = new SignDataResponseV2Dto();
        response.setSignatures(OperationDataMapper.toSignatureData(signed.getSignatures()));
        return response;
    }

    @Override
    public VerifyDataResponseV2Dto verifyData(VerifyDataRequestV2Dto request) {
        KeyContext key = key(request);

        VerifyDataRequestDto verification = new VerifyDataRequestDto();
        verification.setSignatureAttributes(signingParameters(key.key(), request.getSignatureAttributes()));
        verification.setData(OperationDataMapper.toSignatureRequests(request.getData()));
        verification
                .setSignatures(
                        OperationDataMapper.toSignatureRequestsPairedWith(request.getData(), request.getSignatures()));

        VerifyDataResponseDto verified = perform(() -> cryptographicOperationsService
                .verifyData(key.token().instance().getUuid(), key.key().getUuid(), verification));

        VerifyDataResponseV2Dto response = new VerifyDataResponseV2Dto();
        response.setVerifications(OperationDataMapper.toVerifications(verified.getVerifications()));
        return response;
    }

    @Override
    public EncryptDataResponseV2Dto encryptData(CipherDataRequestV2Dto request) {
        KeyContext key = key(request);

        EncryptDataResponseDto encrypted = perform(() -> cryptographicOperationsService
                .encryptData(key.token().instance().getUuid(), key.key().getUuid(), cipher(request)));

        EncryptDataResponseV2Dto response = new EncryptDataResponseV2Dto();
        response.setEncryptedData(OperationDataMapper.toCipherData(encrypted.getEncryptedData()));
        return response;
    }

    @Override
    public DecryptDataResponseV2Dto decryptData(CipherDataRequestV2Dto request) {
        KeyContext key = key(request);

        DecryptDataResponseDto decrypted = perform(() -> cryptographicOperationsService
                .decryptData(key.token().instance().getUuid(), key.key().getUuid(), cipher(request)));

        DecryptDataResponseV2Dto response = new DecryptDataResponseV2Dto();
        response.setDecryptedData(OperationDataMapper.toCipherData(decrypted.getDecryptedData()));
        return response;
    }

    @Override
    public RandomDataResponseV2Dto randomData(RandomDataRequestV2Dto request) {
        TokenContext token = tokenContextService.resolve(request.getTokenAttributes());

        RandomDataRequestDto random = new RandomDataRequestDto();
        random.setLength(request.getLength());
        random.setAttributes(request.getOperationAttributes());

        RandomDataResponseV2Dto response = new RandomDataResponseV2Dto();
        response
                .setData(cryptographicOperationsService
                        .randomData(token.instance().getUuid().toString(), random)
                        .getData());
        return response;
    }

    private static CipherDataRequestDto cipher(CipherDataRequestV2Dto request) {
        CipherDataRequestDto cipher = new CipherDataRequestDto();
        cipher.setCipherAttributes(request.getCipherAttributes());
        cipher.setCipherData(OperationDataMapper.toCipherRequests(request.getCipherData()));
        return cipher;
    }

    private List<RequestAttribute> signingParameters(KeyData key, List<RequestAttribute> attributes) {
        SignatureAlgorithm selected = SignatureAlgorithmAttribute.selectedAlgorithm(attributes);
        if (!supportedAlgorithms(key).contains(selected)) {
            throw new ParameterUnsupportedException("The selected signature algorithm is unavailable for this key");
        }
        if (key.getAlgorithm() != KeyAlgorithm.RSA && key.getAlgorithm() != KeyAlgorithm.ECDSA) {
            return List.of();
        }
        DigestAlgorithm digest = switch (selected) {
            case SHA256_WITH_RSA, SHA256_WITH_RSA_PSS, SHA256_WITH_ECDSA -> DigestAlgorithm.SHA_256;
            case SHA384_WITH_RSA, SHA384_WITH_RSA_PSS, SHA384_WITH_ECDSA -> DigestAlgorithm.SHA_384;
            case SHA512_WITH_RSA, SHA512_WITH_RSA_PSS, SHA512_WITH_ECDSA -> DigestAlgorithm.SHA_512;
            default ->
                throw new ParameterUnsupportedException("The selected signature algorithm is unavailable for this key");
        };
        if (key.getAlgorithm() == KeyAlgorithm.ECDSA) {
            return List.of(string(EcdsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST, digest.getCode()));
        }
        RsaSignatureScheme scheme = selected.name().endsWith("_PSS")
                ? RsaSignatureScheme.PSS
                : RsaSignatureScheme.PKCS1_v1_5;
        return List
                .of(string(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME, scheme.getCode()),
                        string(RsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST, digest.getCode()));
    }

    private static RequestAttribute string(String name, String value) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(new StringAttributeContentV2(value, value)));
        return attribute;
    }

    private KeyContext key(KeyScopedRequestV2Dto request) {
        return keyContextService.resolve(request.getTokenAttributes(), request.getKeyMeta());
    }

    /** The operations report a missing key as a checked absence; the V2 interfaces answer it as the contract states. */
    private static <T> T perform(Operation<T> operation) {
        try {
            return operation.run();
        } catch (NotFoundException e) {
            throw new ResourceMissingException("The addressed key does not exist", e);
        }
    }

    @FunctionalInterface
    private interface Operation<T> {

        T run() throws NotFoundException;
    }

    @Autowired
    public void setCryptographicOperationsService(CryptographicOperationsService cryptographicOperationsService) {
        this.cryptographicOperationsService = cryptographicOperationsService;
    }

    @Autowired
    public void setKeyContextService(KeyContextService keyContextService) {
        this.keyContextService = keyContextService;
    }

    @Autowired
    public void setTokenContextService(TokenContextService tokenContextService) {
        this.tokenContextService = tokenContextService;
    }

    @Autowired
    public void setKeyDataRepository(KeyDataRepository keyDataRepository) {
        this.keyDataRepository = keyDataRepository;
    }
}
