package com.otilm.cp.soft.attribute;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.EncryptionAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaEncryptionScheme;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptionAlgorithmAttribute;
import com.otilm.cp.soft.exception.ParameterUnsupportedException;
import java.util.List;
import java.util.Objects;

/**
 * Publishes explicitly supported V2 cipher profiles and translates their selections into the shared cipher service's
 * parameters.
 */
public final class OperationAttributes {

    private static final List<EncryptionAlgorithm> SUPPORTED_RSA_ALGORITHMS = List
            .of(EncryptionAlgorithm.RSA_PKCS1_V1_5, EncryptionAlgorithm.RSA_OAEP_SHA1,
                    EncryptionAlgorithm.RSA_OAEP_SHA256, EncryptionAlgorithm.RSA_OAEP_SHA384,
                    EncryptionAlgorithm.RSA_OAEP_SHA512);

    private OperationAttributes() {
    }

    /**
     * Defines every encryption profile supported for the given key algorithm, without a key-size restriction.
     *
     * @param algorithm the key's algorithm
     * @return the reserved encryption selector, or no attributes for an unsupported key algorithm
     */
    public static List<BaseAttribute> cipherAttributes(KeyAlgorithm algorithm) {
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        return algorithm == KeyAlgorithm.RSA
                ? List.of(EncryptionAlgorithmAttribute.definition(SUPPORTED_RSA_ALGORITHMS))
                : List.of();
    }

    /**
     * Defines the encryption profiles whose padding fits the addressed key.
     *
     * @param algorithm the key's algorithm
     * @param keyLength the RSA modulus length in bits
     * @return the reserved encryption selector
     * @throws ParameterUnsupportedException when the key has no supported encryption profile
     */
    public static List<BaseAttribute> cipherAttributes(KeyAlgorithm algorithm, int keyLength) {
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        return List.of(EncryptionAlgorithmAttribute.definition(supportedAlgorithms(algorithm, keyLength)));
    }

    /**
     * Checks the key's encryption capability before validating a reserved selection and supplies all parameters fixed
     * by its profile. OAEP uses matching message and MGF1 hashes and the shared cipher's empty label.
     *
     * @param algorithm the key's algorithm
     * @param keyLength the RSA modulus length in bits
     * @param attributes the request's cipher attributes
     * @return parameters understood by the shared V1 cipher service
     * @throws ParameterUnsupportedException when the key has no supported encryption profile or the selected profile is
     * unavailable for this key
     */
    public static List<RequestAttribute> cipherParameters(KeyAlgorithm algorithm, int keyLength,
            List<RequestAttribute> attributes) {
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        List<EncryptionAlgorithm> supported = supportedAlgorithms(algorithm, keyLength);
        EncryptionAlgorithm selected = EncryptionAlgorithmAttribute.selectedAlgorithm(attributes);
        if (!supported.contains(selected)) {
            throw new ParameterUnsupportedException("The selected encryption algorithm is unavailable for this key");
        }
        if (selected == EncryptionAlgorithm.RSA_PKCS1_V1_5) {
            return List
                    .of(string(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME,
                            RsaEncryptionScheme.PKCS1_v1_5.getCode()));
        }
        RequestAttributeV2 mgf = new RequestAttributeV2();
        mgf.setName(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME);
        mgf.setContent(List.of(new BooleanAttributeContentV2(Boolean.TRUE)));
        return List
                .of(string(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME, RsaEncryptionScheme.OAEP.getCode()),
                        string(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME, oaepDigest(selected).getCode()),
                        mgf);
    }

    /**
     * Requires enough modulus bytes for PKCS1 v1.5 padding or the OAEP digest and padding overhead.
     */
    private static List<EncryptionAlgorithm> supportedAlgorithms(KeyAlgorithm algorithm, int keyLength) {
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        int modulusBytes = (keyLength + 7) / 8;
        List<EncryptionAlgorithm> supported = algorithm == KeyAlgorithm.RSA
                ? SUPPORTED_RSA_ALGORITHMS
                        .stream()
                        .filter(profile -> profile == EncryptionAlgorithm.RSA_PKCS1_V1_5
                                ? modulusBytes >= 11
                                : modulusBytes >= 2 * oaepDigest(profile).getDigestSizeBytes() + 2)
                        .toList()
                : List.of();
        if (supported.isEmpty()) {
            throw new ParameterUnsupportedException("This key has no supported encryption algorithm");
        }
        return supported;
    }

    private static DigestAlgorithm oaepDigest(EncryptionAlgorithm algorithm) {
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        return switch (algorithm) {
            case RSA_OAEP_SHA1 -> DigestAlgorithm.SHA_1;
            case RSA_OAEP_SHA256 -> DigestAlgorithm.SHA_256;
            case RSA_OAEP_SHA384 -> DigestAlgorithm.SHA_384;
            case RSA_OAEP_SHA512 -> DigestAlgorithm.SHA_512;
            default ->
                throw new ParameterUnsupportedException("The encryption algorithm has no supported OAEP profile");
        };
    }

    private static RequestAttribute string(String name, String value) {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(value, "value must not be null");
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(new StringAttributeContentV2(value, value)));
        return attribute;
    }
}
