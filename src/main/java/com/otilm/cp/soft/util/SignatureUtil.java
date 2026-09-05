package com.otilm.cp.soft.util;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.connector.cryptography.key.value.CustomKeyValue;
import com.otilm.api.model.connector.cryptography.key.value.SpkiKeyValue;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.cp.soft.attribute.EcdsaKeyAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.ParameterUnsupportedException;
import com.otilm.cp.soft.model.CachedKeyData;
import com.otilm.cp.soft.model.CachedKeyMaterial;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.slhdsa.BCSLHDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class SignatureUtil {

    private SignatureUtil() {
    }

    public static Signature prepareSignature(CachedKeyData key, List<RequestAttribute> signatureAttributes) {
        String signatureAlgorithm;

        switch (key.algorithm()) {
            case RSA -> {
                final RsaSignatureScheme scheme = RsaSignatureScheme
                        .findByCode(AttributeDefinitionUtils
                                .getSingleItemAttributeContentValue(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
                                        signatureAttributes, StringAttributeContentV2.class)
                                .getData());
                final DigestAlgorithm digest = DigestAlgorithm
                        .findByCode(AttributeDefinitionUtils
                                .getSingleItemAttributeContentValue(RsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST,
                                        signatureAttributes, StringAttributeContentV2.class)
                                .getData());

                signatureAlgorithm = digest.getProviderName() + "WITHRSA";
                if (scheme == RsaSignatureScheme.PSS) {
                    signatureAlgorithm += "ANDMGF1";
                }

                return getInstanceSignature(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            }
            case ECDSA -> {
                final DigestAlgorithm digest = DigestAlgorithm
                        .findByCode(AttributeDefinitionUtils
                                .getSingleItemAttributeContentValue(EcdsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST,
                                        signatureAttributes, StringAttributeContentV2.class)
                                .getData());

                signatureAlgorithm = digest.getProviderName() + "WITHECDSA";

                return getInstanceSignature(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            }
            case FALCON -> {
                return getInstanceSignature("FALCON", BouncyCastlePQCProvider.PROVIDER_NAME);
            }
            case MLDSA -> {
                signatureAlgorithm = (isMlDsaPrehash(key) ? "HASH-" : "") + "ML-DSA";
                return getInstanceSignature(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            }
            case SLHDSA -> {
                signatureAlgorithm = (isSlhDsaPrehash(key) ? "HASH-" : "") + "SLH-DSA";
                return getInstanceSignature(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            }
            default -> throw new NotSupportedException("Cryptographic algorithm not supported");
        }
    }

    /**
     * Whether the private key signs a digest of a message rather than the message. A row that does not say cannot be
     * signed with: guessing either way would sign under the wrong parameter set, so the row is reported as the
     * incomplete thing it is rather than dereferenced.
     */
    private static boolean signsADigest(CachedKeyData key) {
        String stated = ((CustomKeyValue) key.value()).getValues().get("prehash");
        if (stated == null) {
            throw new CryptographicOperationException(
                    "The stored key does not say whether it signs a digest, so it cannot be signed with");
        }
        return Boolean.parseBoolean(stated);
    }

    private static boolean isMlDsaPrehash(CachedKeyData key) {
        if (key.type() == KeyType.PRIVATE_KEY) {
            return signsADigest(key);
        }
        SpkiKeyValue spkiKeyValue = (SpkiKeyValue) key.value();
        try {
            BCMLDSAPublicKey pk = new BCMLDSAPublicKey(
                    SubjectPublicKeyInfo.getInstance(Base64.getDecoder().decode(spkiKeyValue.getValue())));
            return pk.getParameterSpec().getName().contains("WITH");
        } catch (IOException e) {
            throw new CryptographicOperationException(
                    "Could not create BCMLDSAPublicKey instance from ML-DSA Public Key value: "
                            + spkiKeyValue.getValue());
        }
    }

    private static boolean isSlhDsaPrehash(CachedKeyData key) {
        if (key.type() == KeyType.PRIVATE_KEY) {
            return signsADigest(key);
        }
        SpkiKeyValue spkiKeyValue = (SpkiKeyValue) key.value();
        try {
            BCSLHDSAPublicKey pk = new BCSLHDSAPublicKey(
                    SubjectPublicKeyInfo.getInstance(Base64.getDecoder().decode(spkiKeyValue.getValue())));
            return pk.getParameterSpec().getName().contains("WITH");
        } catch (IOException e) {
            throw new CryptographicOperationException(
                    "Could not create BCSLHDSAPublicKey instance from SLH-DSA Public Key value: "
                            + spkiKeyValue.getValue());
        }
    }

    /**
     * The signature this request asked for.
     *
     * <p>
     * The scheme and the digest are published as separate choices, so a caller can name a pair no algorithm implements
     * — a digest one scheme signs with and another does not. That is a combination this connector cannot perform rather
     * than a fault of its own, and it is answered as such.
     * </p>
     *
     * @param algorithm the signature algorithm the request's parameters name
     * @param provider the provider that would implement it
     * @return the signature
     */
    public static Signature getInstanceSignature(String algorithm, String provider) {
        try {
            return Signature.getInstance(algorithm, provider);
        } catch (NoSuchAlgorithmException e) {
            throw new ParameterUnsupportedException(
                    "The signature parameters do not name anything this connector can sign with");
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Invalid provider for signature", e);
        }
    }

    public static void initSigning(Signature signature, CachedKeyData key, CachedKeyMaterial material) {
        try {
            signature.initSign(KeyStoreUtil.getPrivateKey(key, material));
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Invalid key '" + key.alias() + "'", e);
        }
    }

    public static void initVerification(Signature signature, CachedKeyData key, CachedKeyMaterial material) {
        try {
            signature.initVerify(KeyStoreUtil.getPublicKey(key, material));
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Invalid key '" + key.alias() + "'", e);
        }
    }

    public static byte[] signData(Signature signature, byte[] data) throws SignatureException {
        signature.update(data);
        return signature.sign();
    }

    public static boolean verifyData(Signature signature, byte[] data, byte[] sign) throws SignatureException {
        signature.update(data);
        return signature.verify(sign);
    }
}
