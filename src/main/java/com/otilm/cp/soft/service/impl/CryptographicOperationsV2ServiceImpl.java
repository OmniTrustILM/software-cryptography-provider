package com.otilm.cp.soft.service.impl;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
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
import com.otilm.cp.soft.exception.CryptographicOperationException;
import com.otilm.cp.soft.exception.ParameterUnsupportedException;
import com.otilm.cp.soft.model.CachedKeyData;
import com.otilm.cp.soft.model.OperationKey;
import com.otilm.cp.soft.model.TokenContext;
import com.otilm.cp.soft.service.CryptographicOperationsService;
import com.otilm.cp.soft.service.CryptographicOperationsV2Service;
import com.otilm.cp.soft.service.KeyContextService;
import com.otilm.cp.soft.service.TokenContextService;
import com.otilm.cp.soft.util.KeyStoreUtil;
import com.otilm.cp.soft.util.OperationDataMapper;
import com.otilm.cp.soft.util.RequestAttributes;
import com.otilm.cp.soft.util.RsaEncodingConstants;
import com.otilm.cp.soft.util.SignatureAlgorithms;
import java.util.Base64;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * V2 operations use the keys stored for both interface versions. Key-scoped requests resolve token and key metadata,
 * and execution delegates to the shared cryptographic service.
 */
@Service
public class CryptographicOperationsV2ServiceImpl implements CryptographicOperationsV2Service {

    private static final Set<SignatureAlgorithm> RSA_PSS_ALGORITHMS = EnumSet
            .of(SignatureAlgorithm.SHA256_WITH_RSA_PSS, SignatureAlgorithm.SHA384_WITH_RSA_PSS,
                    SignatureAlgorithm.SHA512_WITH_RSA_PSS);

    /** The digest each RSA and ECDSA algorithm signs, which the shared signer is told as a parameter of its own. */
    private static final Map<SignatureAlgorithm, DigestAlgorithm> DIGESTS = new EnumMap<>(Map
            .of(SignatureAlgorithm.SHA256_WITH_RSA, DigestAlgorithm.SHA_256, SignatureAlgorithm.SHA384_WITH_RSA,
                    DigestAlgorithm.SHA_384, SignatureAlgorithm.SHA512_WITH_RSA, DigestAlgorithm.SHA_512,
                    SignatureAlgorithm.SHA256_WITH_RSA_PSS, DigestAlgorithm.SHA_256,
                    SignatureAlgorithm.SHA384_WITH_RSA_PSS, DigestAlgorithm.SHA_384,
                    SignatureAlgorithm.SHA512_WITH_RSA_PSS, DigestAlgorithm.SHA_512,
                    SignatureAlgorithm.SHA256_WITH_ECDSA, DigestAlgorithm.SHA_256, SignatureAlgorithm.SHA384_WITH_ECDSA,
                    DigestAlgorithm.SHA_384, SignatureAlgorithm.SHA512_WITH_ECDSA, DigestAlgorithm.SHA_512));

    private CryptographicOperationsService cryptographicOperationsService;

    private KeyContextService keyContextService;

    private TokenContextService tokenContextService;

    @Override
    public List<BaseAttribute> signatureAttributes(KeyScopedRequestV2Dto request) {
        return List.of(SignatureAlgorithmAttribute.definition(supportedAlgorithms(resolveForOperation(request))));
    }

    private static List<SignatureAlgorithm> supportedAlgorithms(OperationKey operationKey) {
        CachedKeyData key = operationKey.key();
        List<SignatureAlgorithm> supported = switch (key.algorithm()) {
            case RSA -> SignatureAlgorithms
                    .offeredFor(KeyAlgorithm.RSA)
                    .stream()
                    .filter(algorithm -> fitsRsaKey(algorithm, key.length()))
                    .toList();
            case FALCON, MLDSA, SLHDSA -> supportedPostQuantumAlgorithm(operationKey);
            default -> SignatureAlgorithms.offeredFor(key.algorithm());
        };
        if (supported.isEmpty()) {
            throw new ParameterUnsupportedException("This key has no supported signature algorithm");
        }
        return supported;
    }

    /**
     * Checks whether the signature's digest and padding fit the RSA modulus.
     */
    private static boolean fitsRsaKey(SignatureAlgorithm algorithm, int modulusBits) {
        int digestBytes = DIGESTS.get(algorithm).getDigestSizeBytes();
        if (RSA_PSS_ALGORITHMS.contains(algorithm)) {
            int encodedBytes = (modulusBits + 6) / 8;
            return encodedBytes >= 2 * digestBytes + RsaEncodingConstants.PSS_PADDING_BYTES;
        }
        int modulusBytes = (modulusBits + 7) / 8;
        return modulusBytes >= RsaEncodingConstants.DIGEST_INFO_PREFIX_BYTES + digestBytes
                + RsaEncodingConstants.PKCS1_V1_5_PADDING_BYTES;
    }

    /**
     * A public row states its own public key. A private key's public key is in the certificate the keystore keeps under
     * the same alias.
     */
    private static List<SignatureAlgorithm> supportedPostQuantumAlgorithm(OperationKey operationKey) {
        CachedKeyData key = operationKey.key();
        try {
            byte[] publicKey = key.type() == KeyType.PUBLIC_KEY
                    ? Base64.getDecoder().decode(((SpkiKeyValue) key.value()).getValue())
                    : KeyStoreUtil.getPublicKey(key, operationKey.material()).getEncoded();
            ASN1ObjectIdentifier oid = SubjectPublicKeyInfo.getInstance(publicKey).getAlgorithm().getAlgorithm();
            return SignatureAlgorithms
                    .offeredFor(key.algorithm())
                    .stream()
                    .filter(algorithm -> oid.equals(algorithm.getAlgorithmIdentifier().getAlgorithm()))
                    .toList();
        } catch (IllegalArgumentException | ClassCastException e) {
            throw new CryptographicOperationException("The stored public key has invalid signature parameters");
        }
    }

    /**
     * Offers the reserved encryption profiles supported by the addressed key and its modulus size.
     */
    @Override
    public List<BaseAttribute> cipherAttributes(KeyScopedRequestV2Dto request) {
        Objects.requireNonNull(request, "request must not be null");
        CachedKeyData key = resolveForOperation(request).key();
        return OperationAttributes.cipherAttributes(key.algorithm(), key.length());
    }

    @Override
    public List<BaseAttribute> randomAttributes(TokenProfileScopedRequestV2Dto request) {
        tokenContextService.locate(request.getTokenAttributes());
        return List.of();
    }

    @Override
    public SignDataResponseV2Dto signData(SignDataRequestV2Dto request) {
        OperationKey operationKey = resolveForOperation(request);

        SignDataRequestDto signing = new SignDataRequestDto();
        signing.setSignatureAttributes(signingParameters(operationKey, request.getSignatureAttributes()));
        signing.setData(OperationDataMapper.toSignatureRequests(request.getData()));

        SignDataResponseDto signed = cryptographicOperationsService.signData(operationKey, signing);

        SignDataResponseV2Dto response = new SignDataResponseV2Dto();
        response.setSignatures(OperationDataMapper.toSignatures(signed.getSignatures()));
        return response;
    }

    @Override
    public VerifyDataResponseV2Dto verifyData(VerifyDataRequestV2Dto request) {
        OperationKey operationKey = resolveForOperation(request);

        VerifyDataRequestDto verification = new VerifyDataRequestDto();
        verification.setSignatureAttributes(signingParameters(operationKey, request.getSignatureAttributes()));
        verification.setData(OperationDataMapper.toSignatureRequests(request.getData()));
        verification
                .setSignatures(
                        OperationDataMapper.toSignatureRequestsPairedWith(request.getData(), request.getSignatures()));

        VerifyDataResponseDto verified = cryptographicOperationsService.verifyData(operationKey, verification);

        VerifyDataResponseV2Dto response = new VerifyDataResponseV2Dto();
        response.setVerifications(OperationDataMapper.toVerifications(verified.getVerifications()));
        return response;
    }

    /**
     * Encrypts with the selected V2 profile using the shared cipher service.
     */
    @Override
    public EncryptDataResponseV2Dto encryptData(CipherDataRequestV2Dto request) {
        Objects.requireNonNull(request, "request must not be null");
        OperationKey operationKey = resolveForOperation(request);

        EncryptDataResponseDto encrypted = cryptographicOperationsService
                .encryptData(operationKey, cipher(operationKey.key(), request));

        EncryptDataResponseV2Dto response = new EncryptDataResponseV2Dto();
        response.setEncryptedData(OperationDataMapper.toCipherData(encrypted.getEncryptedData()));
        return response;
    }

    /**
     * Decrypts with the selected V2 profile using the shared cipher service.
     */
    @Override
    public DecryptDataResponseV2Dto decryptData(CipherDataRequestV2Dto request) {
        Objects.requireNonNull(request, "request must not be null");
        OperationKey operationKey = resolveForOperation(request);

        DecryptDataResponseDto decrypted = cryptographicOperationsService
                .decryptData(operationKey, cipher(operationKey.key(), request));

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

    /**
     * Adapts the reserved algorithm selection and batch data to the shared cipher request.
     */
    private static CipherDataRequestDto cipher(CachedKeyData key, CipherDataRequestV2Dto request) {
        CipherDataRequestDto cipher = new CipherDataRequestDto();
        cipher
                .setCipherAttributes(OperationAttributes
                        .cipherParameters(key.algorithm(), key.length(), request.getCipherAttributes()));
        cipher.setCipherData(OperationDataMapper.toCipherRequests(request.getCipherData()));
        return cipher;
    }

    /**
     * Translates a supported reserved signature selection into the shared signer's parameters.
     */
    private static List<RequestAttribute> signingParameters(OperationKey operationKey,
            List<RequestAttribute> attributes) {
        SignatureAlgorithm selected = SignatureAlgorithmAttribute.selectedAlgorithm(attributes);
        if (!supportedAlgorithms(operationKey).contains(selected)) {
            throw new ParameterUnsupportedException("The selected signature algorithm is unavailable for this key");
        }
        return switch (operationKey.key().algorithm()) {
            case RSA -> {
                RsaSignatureScheme scheme = RSA_PSS_ALGORITHMS.contains(selected)
                        ? RsaSignatureScheme.PSS
                        : RsaSignatureScheme.PKCS1_v1_5;
                yield List
                        .of(RequestAttributes.string(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME, scheme.getCode()),
                                RequestAttributes
                                        .string(RsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST,
                                                DIGESTS.get(selected).getCode()));
            }
            case ECDSA -> List
                    .of(RequestAttributes
                            .string(EcdsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST, DIGESTS.get(selected).getCode()));
            default -> List.of();
        };
    }

    private OperationKey resolveForOperation(KeyScopedRequestV2Dto request) {
        return keyContextService.resolveForOperation(request.getTokenAttributes(), request.getKeyMeta());
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
}
