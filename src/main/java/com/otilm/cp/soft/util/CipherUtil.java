package com.otilm.cp.soft.util;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaEncryptionScheme;
import com.otilm.api.model.connector.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.connector.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.EncryptDataResponseDto;
import com.otilm.api.model.connector.cryptography.operations.data.CipherRequestData;
import com.otilm.api.model.connector.cryptography.operations.data.CipherResponseData;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.cp.soft.attribute.RsaCipherAttributes;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.model.CachedKeyData;
import com.otilm.cp.soft.model.CachedKeyMaterial;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CipherUtil {

    /**
     * Bundles a JCE transformation string with an optional {@link AlgorithmParameterSpec}. The parameter spec is
     * non-null only when the transformation string alone is not sufficient to fully describe the cipher configuration
     * (such as OAEP with a MGF1 hash that differs from the main digest hash).
     */
    private record CipherSpec(String transformation, AlgorithmParameterSpec parameterSpec) {
    }

    public static DecryptDataResponseDto decrypt(CipherDataRequestDto request, CachedKeyData key,
            CachedKeyMaterial material) {
        if (key.algorithm() == KeyAlgorithm.RSA) {
            List<RequestAttribute> attributes = request.getCipherAttributes();
            RsaEncryptionScheme rsaEncryptionScheme = RsaEncryptionScheme
                    .findByCode(AttributeDefinitionUtils
                            .getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME,
                                    attributes, StringAttributeContentV2.class)
                            .getData());
            return decryptData(request, key, material,
                    getCipherSpec(rsaEncryptionScheme, request.getCipherAttributes()));
        } else {
            throw new NotSupportedException("Algorithm not supported");
        }
    }

    public static EncryptDataResponseDto encrypt(CipherDataRequestDto request, CachedKeyData key,
            CachedKeyMaterial material) {
        if (key.algorithm() == KeyAlgorithm.RSA) {
            List<RequestAttribute> attributes = request.getCipherAttributes();
            RsaEncryptionScheme rsaEncryptionScheme = RsaEncryptionScheme
                    .findByCode(AttributeDefinitionUtils
                            .getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME,
                                    attributes, StringAttributeContentV2.class)
                            .getData());
            return encryptData(request, key, material,
                    getCipherSpec(rsaEncryptionScheme, request.getCipherAttributes()));
        } else {
            throw new NotSupportedException("Algorithm not supported");
        }
    }

    private static DecryptDataResponseDto decryptData(CipherDataRequestDto request, CachedKeyData key,
            CachedKeyMaterial material, CipherSpec cipherSpec) {
        DecryptDataResponseDto responseDto = new DecryptDataResponseDto();
        responseDto
                .setDecryptedData(doProcess(request.getCipherData(), Cipher.DECRYPT_MODE, cipherSpec, key, material));
        return responseDto;
    }

    private static EncryptDataResponseDto encryptData(CipherDataRequestDto request, CachedKeyData key,
            CachedKeyMaterial material, CipherSpec cipherSpec) {
        EncryptDataResponseDto responseDto = new EncryptDataResponseDto();
        responseDto
                .setEncryptedData(doProcess(request.getCipherData(), Cipher.ENCRYPT_MODE, cipherSpec, key, material));
        return responseDto;
    }

    private static List<CipherResponseData> doProcess(List<CipherRequestData> cipherData, int mode,
            CipherSpec cipherSpec, CachedKeyData key, CachedKeyMaterial material) {
        Iterator<CipherRequestData> it = cipherData.stream().iterator();
        List<CipherResponseData> responseDataList = new ArrayList<>();
        while (it.hasNext()) {
            try {
                byte[] encBytes = it.next().getData();
                Cipher cipher = Cipher.getInstance(cipherSpec.transformation(), BouncyCastleProvider.PROVIDER_NAME);
                // RSA encryption must use the public key; decryption must use the private key.
                Key cryptoKey = (mode == Cipher.ENCRYPT_MODE)
                        ? KeyStoreUtil.getPublicKey(key, material)
                        : KeyStoreUtil.getPrivateKey(key, material);
                if (cipherSpec.parameterSpec() != null) {
                    cipher.init(mode, cryptoKey, cipherSpec.parameterSpec());
                } else {
                    cipher.init(mode, cryptoKey);
                }
                CipherResponseData cipherResponseData = new CipherResponseData();
                cipherResponseData.setData(cipher.doFinal(encBytes));
                responseDataList.add(cipherResponseData);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException | InvalidKeyException
                    | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
                throw new ValidationException(
                        ValidationError.create("Exception when processing cipher data: " + e.getMessage()));
            }
        }
        return responseDataList;
    }

    private static CipherSpec getCipherSpec(RsaEncryptionScheme rsaEncryptionScheme,
            List<RequestAttribute> attributes) {
        if (rsaEncryptionScheme.equals(RsaEncryptionScheme.PKCS1_v1_5)) {
            return new CipherSpec("RSA/NONE/PKCS1Padding", null);
        } else if (rsaEncryptionScheme.equals(RsaEncryptionScheme.OAEP)) {
            try {
                DigestAlgorithm hash = DigestAlgorithm
                        .findByCode(AttributeDefinitionUtils
                                .getSingleItemAttributeContentValue(
                                        RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME, attributes,
                                        StringAttributeContentV2.class)
                                .getData());
                boolean useMgf = AttributeDefinitionUtils
                        .getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME,
                                attributes, BooleanAttributeContentV2.class)
                        .getData();
                return buildOaepCipherSpec(hash, useMgf);
            } catch (Exception e) {
                throw new ValidationException("Invalid attributes for OAEP");
            }
        } else {
            throw new NotSupportedException("Transformation type not supported");
        }
    }

    /**
     * Builds the {@link CipherSpec} for RSA-OAEP.
     *
     * <p>
     * When {@code useMgf} is {@code true} the same digest algorithm is used for both the OAEP hash and MGF1 — expressed
     * entirely through the JCE transformation string (such as {@code RSA/NONE/OAEPWithSHA256AndMGF1Padding}).
     *
     * <p>
     * When {@code useMgf} is {@code false} the specified digest is used only for the OAEP hash while MGF1 falls back to
     * SHA-1, which is the default defined in RFC 8017 §7.1. Because no JCE transformation string exists for this
     * split-hash variant, the same transformation string is reused but an explicit {@link OAEPParameterSpec} is
     * attached that overrides the MGF1 hash to SHA-1.
     */
    private static CipherSpec buildOaepCipherSpec(DigestAlgorithm hash, boolean useMgf) {
        String transformation = "RSA/NONE/OAEPWith" + hash.getProviderName() + "AndMGF1Padding";
        if (useMgf) {
            // Hash and MGF1 both use the specified digest — transformation string is sufficient.
            return new CipherSpec(transformation, null);
        } else {
            // Hash uses the specified digest; MGF1 uses SHA-1 (RFC 8017 default).
            OAEPParameterSpec spec = new OAEPParameterSpec(toJcaHashName(hash), "MGF1", MGF1ParameterSpec.SHA1,
                    PSource.PSpecified.DEFAULT);
            return new CipherSpec(transformation, spec);
        }
    }

    private static String toJcaHashName(DigestAlgorithm hash) {
        return switch (hash) {
            case SHA_256 -> "SHA-256";
            case SHA_384 -> "SHA-384";
            case SHA_512 -> "SHA-512";
            default -> throw new NotSupportedException("Hash algorithm not supported for OAEP: " + hash);
        };
    }
}
