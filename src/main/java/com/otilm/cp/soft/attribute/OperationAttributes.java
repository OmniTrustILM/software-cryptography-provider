package com.otilm.cp.soft.attribute;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaEncryptionScheme;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import java.util.List;
import java.util.stream.Stream;

/**
 * What an operation needs to be told, beyond the key it runs on.
 *
 * <p>
 * The provider has always read these attributes when signing or encrypting; the V2 interfaces are the first to publish
 * their schema, so a caller can populate them from the document rather than knowing them in advance. Which ones apply
 * depends on the key's algorithm: the post-quantum signature algorithms carry every parameter in the key itself and
 * need nothing here.
 * </p>
 */
public final class OperationAttributes {

    public static final String ATTRIBUTE_DATA_RSA_SIG_SCHEME_UUID = "b7a1c084-16a3-4a2b-9f56-4d7f0f0a3c11";
    public static final String ATTRIBUTE_DATA_RSA_SIG_SCHEME_LABEL = "RSA Signature Scheme";
    public static final String ATTRIBUTE_DATA_RSA_SIG_SCHEME_DESCRIPTION = "Select the RSA signature scheme to use";

    public static final String ATTRIBUTE_DATA_SIG_DIGEST_UUID = "c1f5d0e2-6b48-4d6c-9a3e-2f2b9c7d54ab";
    public static final String ATTRIBUTE_DATA_SIG_DIGEST_LABEL = "Signature Digest";
    public static final String ATTRIBUTE_DATA_SIG_DIGEST_DESCRIPTION = "Select the digest to sign with";

    public static final String ATTRIBUTE_DATA_RSA_ENC_SCHEME_UUID = "d4c3b2a1-9e87-4f65-8d21-0a1b2c3d4e5f";
    public static final String ATTRIBUTE_DATA_RSA_ENC_SCHEME_LABEL = "RSA Encryption Scheme";
    public static final String ATTRIBUTE_DATA_RSA_ENC_SCHEME_DESCRIPTION = "Select the RSA encryption scheme to use";

    public static final String ATTRIBUTE_DATA_RSA_OAEP_HASH_UUID = "e5a49b73-1c2d-4e8f-b0a6-7d8e9f0a1b2c";
    public static final String ATTRIBUTE_DATA_RSA_OAEP_HASH_LABEL = "OAEP Hash";
    public static final String ATTRIBUTE_DATA_RSA_OAEP_HASH_DESCRIPTION = "Hash used by OAEP padding, required when the encryption scheme is OAEP";

    public static final String ATTRIBUTE_DATA_RSA_OAEP_MGF_UUID = "f6b58c84-2d3e-4f90-a1b7-8e9f0a1b2c3d";
    public static final String ATTRIBUTE_DATA_RSA_OAEP_MGF_LABEL = "OAEP Mask Generation";
    public static final String ATTRIBUTE_DATA_RSA_OAEP_MGF_DESCRIPTION = "Whether OAEP padding uses MGF1, required when the encryption scheme is OAEP";

    private OperationAttributes() {
    }

    /**
     * What signing or verifying with a key of the given algorithm needs to be told.
     *
     * @param algorithm the key's algorithm
     * @return the attribute schema, empty when the algorithm needs nothing
     */
    public static List<BaseAttribute> signatureAttributes(KeyAlgorithm algorithm) {
        return switch (algorithm) {
            case RSA -> List.of(buildRsaSignatureScheme(), buildSignatureDigest());
            case ECDSA -> List.of(buildSignatureDigest());
            default -> List.of();
        };
    }

    /**
     * What encrypting or decrypting with a key of the given algorithm needs to be told.
     *
     * @param algorithm the key's algorithm
     * @return the attribute schema, empty when the algorithm cannot be used this way
     */
    public static List<BaseAttribute> cipherAttributes(KeyAlgorithm algorithm) {
        if (algorithm != KeyAlgorithm.RSA) {
            return List.of();
        }
        return List.of(buildRsaEncryptionScheme(), buildRsaOaepHash(), buildRsaOaepMaskGeneration());
    }

    private static BaseAttribute buildRsaSignatureScheme() {
        return select(ATTRIBUTE_DATA_RSA_SIG_SCHEME_UUID, RsaKeyAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
                ATTRIBUTE_DATA_RSA_SIG_SCHEME_LABEL, ATTRIBUTE_DATA_RSA_SIG_SCHEME_DESCRIPTION, true,
                Stream
                        .of(RsaSignatureScheme.values())
                        .map(scheme -> new StringAttributeContentV2(scheme.getLabel(), scheme.getCode()))
                        .toList());
    }

    private static BaseAttribute buildSignatureDigest() {
        return select(ATTRIBUTE_DATA_SIG_DIGEST_UUID, RsaKeyAttributes.ATTRIBUTE_DATA_SIG_DIGEST,
                ATTRIBUTE_DATA_SIG_DIGEST_LABEL, ATTRIBUTE_DATA_SIG_DIGEST_DESCRIPTION, true,
                Stream
                        .of(DigestAlgorithm.values())
                        .map(digest -> new StringAttributeContentV2(digest.getLabel(), digest.getCode()))
                        .toList());
    }

    private static BaseAttribute buildRsaEncryptionScheme() {
        return select(ATTRIBUTE_DATA_RSA_ENC_SCHEME_UUID, RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME,
                ATTRIBUTE_DATA_RSA_ENC_SCHEME_LABEL, ATTRIBUTE_DATA_RSA_ENC_SCHEME_DESCRIPTION, true,
                Stream
                        .of(RsaEncryptionScheme.values())
                        .map(scheme -> new StringAttributeContentV2(scheme.getLabel(), scheme.getCode()))
                        .toList());
    }

    private static BaseAttribute buildRsaOaepHash() {
        return select(ATTRIBUTE_DATA_RSA_OAEP_HASH_UUID, RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME,
                ATTRIBUTE_DATA_RSA_OAEP_HASH_LABEL, ATTRIBUTE_DATA_RSA_OAEP_HASH_DESCRIPTION, false,
                Stream
                        .of(DigestAlgorithm.values())
                        .map(digest -> new StringAttributeContentV2(digest.getLabel(), digest.getCode()))
                        .toList());
    }

    private static BaseAttribute buildRsaOaepMaskGeneration() {
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_RSA_OAEP_MGF_UUID);
        attribute.setName(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME);
        attribute.setDescription(ATTRIBUTE_DATA_RSA_OAEP_MGF_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.BOOLEAN);

        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(ATTRIBUTE_DATA_RSA_OAEP_MGF_LABEL);
        properties.setRequired(false);
        properties.setVisible(true);
        properties.setReadOnly(false);
        attribute.setProperties(properties);
        attribute.setContent(List.of(new BooleanAttributeContentV2(Boolean.TRUE)));

        return attribute;
    }

    private static BaseAttribute select(String uuid, String name, String label, String description, boolean required,
            List<StringAttributeContentV2> content) {
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(uuid);
        attribute.setName(name);
        attribute.setDescription(description);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);

        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(label);
        properties.setRequired(required);
        properties.setVisible(true);
        properties.setList(true);
        properties.setMultiSelect(false);
        properties.setReadOnly(false);
        attribute.setProperties(properties);
        attribute.setContent(content);

        return attribute;
    }
}
