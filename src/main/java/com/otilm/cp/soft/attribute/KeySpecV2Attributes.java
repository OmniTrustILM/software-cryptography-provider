package com.otilm.cp.soft.attribute;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.GroupAttributeV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.cp.soft.collection.FalconDegree;
import com.otilm.cp.soft.collection.SLHDSAHash;
import com.otilm.cp.soft.exception.ParameterUnsupportedException;
import java.util.List;
import java.util.Set;

/**
 * The key specification V2 key creation asks for. V2 creates a signing key only in a parameter set a platform signature
 * algorithm names, so it leaves out the choices V1 offers beyond them and creates every key with the one value it
 * offers there.
 *
 * <p>
 * The children are V1's own definitions, never altered ones, since the platform keeps one definition per identifier for
 * a connector whichever interface published it. The group is V2's own because V1's resolves through a V1 callback.
 * </p>
 */
public final class KeySpecV2Attributes {

    public static final String ATTRIBUTE_GROUP_KEY_SPEC = "group_keySpecV2";
    public static final String ATTRIBUTE_GROUP_KEY_SPEC_UUID = "05927c10-b5ca-43cb-a69f-098885b8c307";

    private KeySpecV2Attributes() {
    }

    /** The group, resolved through the V2 attributes callback once the key algorithm is chosen. */
    public static BaseAttribute buildGroup() {
        AttributeCallback callback = new AttributeCallback();
        callback.setDependsOn(List.of(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM));
        callback.setMappings(Set.of());

        GroupAttributeV3 group = new GroupAttributeV3();
        group.setUuid(ATTRIBUTE_GROUP_KEY_SPEC_UUID);
        group.setName(ATTRIBUTE_GROUP_KEY_SPEC);
        group.setDescription(KeyAttributes.ATTRIBUTE_GROUP_KEY_SPEC_LABEL);
        group.setAttributeCallback(callback);
        return group;
    }

    /**
     * What creating a key of the given algorithm asks for.
     *
     * @param algorithm the chosen key algorithm
     * @return the group's children
     * @throws ParameterUnsupportedException when this connector creates no key of the algorithm
     */
    public static List<BaseAttribute> forAlgorithm(KeyAlgorithm algorithm) {
        return switch (algorithm) {
            case RSA -> RsaKeyAttributes.getRsaKeySpecAttributes();
            case ECDSA -> EcdsaKeyAttributes.getEcdsaKeySpecAttributes();
            case FALCON -> List.of();
            case MLDSA -> List.of(MLDSAKeyAttributes.buildDataMLDSASecurityCategory());
            case SLHDSA ->
                List.of(SLHDSAKeyAttributes.buildDataSecurityCategory(), SLHDSAKeyAttributes.buildDataSignatureMode());
            case MLKEM -> MLKEMAttributes.getMLKEMKeySpecAttributes();
            default -> throw new ParameterUnsupportedException("This connector creates no " + algorithm + " key");
        };
    }

    /**
     * The value V2 creates a key of the given algorithm with, for each choice it leaves out.
     *
     * @param algorithm the chosen key algorithm
     * @return what a creation states for those choices
     */
    public static List<RequestAttribute> fixedParameters(KeyAlgorithm algorithm) {
        return switch (algorithm) {
            case FALCON -> List
                    .of(stated(FalconKeyAttributes.ATTRIBUTE_DATA_FALCON_DEGREE, new IntegerAttributeContentV2(
                            FalconDegree.FALCON_1024.name(), FalconDegree.FALCON_1024.getDegree())));
            case MLDSA ->
                List.of(stated(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_PREHASH, new BooleanAttributeContentV2(false)));
            case SLHDSA -> List
                    .of(stated(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_HASH,
                            new StringAttributeContentV2(SLHDSAHash.SHA2.name(), SLHDSAHash.SHA2.getHashName())),
                            stated(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_PREHASH,
                                    new BooleanAttributeContentV2(false)));
            default -> List.of();
        };
    }

    private static RequestAttribute stated(String name, BaseAttributeContentV2<?> content) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(content));
        return attribute;
    }
}
