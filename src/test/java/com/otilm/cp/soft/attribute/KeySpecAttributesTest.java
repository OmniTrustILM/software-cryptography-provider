package com.otilm.cp.soft.attribute;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.cp.soft.collection.EcdsaCurveName;
import com.otilm.cp.soft.collection.FalconDegree;
import com.otilm.cp.soft.collection.MLDSASecurityCategory;
import com.otilm.cp.soft.collection.MLKEMSecurityCategory;
import com.otilm.cp.soft.collection.RsaKeySize;
import com.otilm.cp.soft.collection.SLHDSAHash;
import com.otilm.cp.soft.collection.SLHDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASignatureMode;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.cp.soft.attribute.AttributeAssert.assertDataAttribute;
import static com.otilm.cp.soft.attribute.AttributeAssert.assertSelectionList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The key specification attributes offered per algorithm. Each is identified by a UUID the platform stores against a
 * generated key, and each offers the options its collection defines.
 */
class KeySpecAttributesTest {

    private static Stream<Arguments> selectionAttributes() {
        return Stream
                .of(Arguments
                        .of(RsaKeyAttributes.buildDataRsaKeySize(), RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE_UUID,
                                RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE, AttributeContentType.INTEGER,
                                RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE_LABEL, RsaKeySize.values().length, true),
                        Arguments
                                .of(EcdsaKeyAttributes.buildDataEscdaNamedCurves(),
                                        EcdsaKeyAttributes.ATTRIBUTE_DATA_ECDSA_CURVE_UUID,
                                        EcdsaKeyAttributes.ATTRIBUTE_DATA_ECDSA_CURVE, AttributeContentType.STRING,
                                        EcdsaKeyAttributes.ATTRIBUTE_DATA_ECDSA_CURVE_LABEL,
                                        EcdsaCurveName.values().length, true),
                        Arguments
                                .of(FalconKeyAttributes.buildDataFalconDegree(),
                                        FalconKeyAttributes.ATTRIBUTE_DATA_FALCON_DEGREE_UUID,
                                        FalconKeyAttributes.ATTRIBUTE_DATA_FALCON_DEGREE, AttributeContentType.INTEGER,
                                        FalconKeyAttributes.ATTRIBUTE_DATA_FALCON_DEGREE_LABEL,
                                        FalconDegree.values().length, true),
                        Arguments
                                .of(MLDSAKeyAttributes.buildDataMLDSASecurityCategory(),
                                        MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_LEVEL_UUID,
                                        MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_LEVEL, AttributeContentType.INTEGER,
                                        MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_LEVEL_LABEL,
                                        MLDSASecurityCategory.values().length, true),
                        Arguments
                                .of(MLKEMAttributes.buildDataMLKEMSecurityCategory(),
                                        MLKEMAttributes.ATTRIBUTE_DATA_MLKEM_LEVEL_UUID,
                                        MLKEMAttributes.ATTRIBUTE_DATA_MLKEM_LEVEL, AttributeContentType.INTEGER,
                                        MLKEMAttributes.ATTRIBUTE_DATA_MLKEM_LEVEL_LABEL,
                                        MLKEMSecurityCategory.values().length, true),
                        Arguments
                                .of(SLHDSAKeyAttributes.buildDataSecurityCategory(),
                                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY_UUID,
                                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY,
                                        AttributeContentType.STRING,
                                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY_LABEL,
                                        SLHDSASecurityCategory.values().length, true),
                        Arguments
                                .of(SLHDSAKeyAttributes.buildDataHash(),
                                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_HASH_UUID,
                                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_HASH, AttributeContentType.STRING,
                                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_HASH_LABEL,
                                        SLHDSAHash.values().length, true),
                        // The only optional key specification attribute: without it the signature
                        // generation mode falls back to the algorithm default.
                        Arguments
                                .of(SLHDSAKeyAttributes.buildDataSignatureMode(),
                                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE_UUID,
                                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE,
                                        AttributeContentType.STRING,
                                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE_LABEL,
                                        SLHDSASignatureMode.values().length, false));
    }

    @ParameterizedTest(name = "{2}")
    @MethodSource("selectionAttributes")
    void keySpecAttributeIsASelectionOverItsCollection(BaseAttribute attribute, String uuid, String name,
            AttributeContentType contentType, String label, int optionCount, boolean required) {
        DataAttributeV2 data = assertDataAttribute(attribute, uuid, name, contentType, label);
        assertSelectionList(data, required);
        assertEquals(optionCount, data.getContent().size(), name + " does not offer every option");
        assertTrue(data.getProperties().isVisible(), name + " must be visible");
        assertFalse(data.getProperties().isReadOnly(), name + " must be editable");
    }

    private static Stream<Arguments> preHashAttributes() {
        return Stream
                .of(Arguments
                        .of(MLDSAKeyAttributes.buildBooleanPreHash(),
                                MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_PREHASH_UUID,
                                MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_PREHASH,
                                MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_PREHASH_LABEL),
                        Arguments
                                .of(SLHDSAKeyAttributes.buildBooleanPreHash(),
                                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_PREHASH_UUID,
                                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_PREHASH,
                                        SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_PREHASH_LABEL));
    }

    @ParameterizedTest(name = "{2}")
    @MethodSource("preHashAttributes")
    void preHashDefaultsToOff(BaseAttribute attribute, String uuid, String name, String label) {
        DataAttributeV2 data = assertDataAttribute(attribute, uuid, name, AttributeContentType.BOOLEAN, label);
        // The default decides whether a generated key is intended for pure or pre-hash
        // signing, which cannot be changed afterwards.
        assertEquals(1, data.getContent().size());
        assertEquals(Boolean.FALSE, data.getContent().get(0).getData(), name + " must default to off");
        assertFalse(data.getProperties().isList(), name + " is a flag, not a list");
    }

    @Test
    void eachAlgorithmOffersItsOwnSpecificationSet() {
        assertEquals(List.of(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE),
                names(RsaKeyAttributes.getRsaKeySpecAttributes()));
        assertEquals(List.of(EcdsaKeyAttributes.ATTRIBUTE_DATA_ECDSA_CURVE),
                names(EcdsaKeyAttributes.getEcdsaKeySpecAttributes()));
        assertEquals(List.of(FalconKeyAttributes.ATTRIBUTE_DATA_FALCON_DEGREE),
                names(FalconKeyAttributes.getFalconKeySpecAttributes()));
        assertEquals(List.of(MLKEMAttributes.ATTRIBUTE_DATA_MLKEM_LEVEL),
                names(MLKEMAttributes.getMLKEMKeySpecAttributes()));
        assertEquals(
                List.of(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_LEVEL, MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_PREHASH),
                names(MLDSAKeyAttributes.getMldsaKeySpecAttributes()));
        assertEquals(
                List
                        .of(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY,
                                SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_HASH,
                                SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE,
                                SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_PREHASH),
                names(SLHDSAKeyAttributes.getSlhDsaKeySpecAttributes()));
    }

    @Test
    void rsaKeySizeMetadataRecordsTheGeneratedSize() {
        MetadataAttribute metadata = RsaKeyAttributes.buildRsaKeySizeMetadata(4096);
        assertEquals(RsaKeyAttributes.ATTRIBUTE_META_RSA_KEY_SIZE_UUID, metadata.getUuid());
        assertEquals(RsaKeyAttributes.ATTRIBUTE_META_RSA_KEY_SIZE, metadata.getName());
        assertEquals(AttributeType.META, metadata.getType());
        assertEquals("size", contentOf(metadata).get(0).getReference());
        assertEquals(4096, contentOf(metadata).get(0).getData());
    }

    @Test
    void falconDegreeMetadataRecordsTheGeneratedDegree() {
        MetadataAttribute metadata = FalconKeyAttributes.buildFalconDegreeMetadata(1024);
        assertEquals(FalconKeyAttributes.ATTRIBUTE_META_FALCON_DEGREE_UUID, metadata.getUuid());
        assertEquals(FalconKeyAttributes.ATTRIBUTE_META_FALCON_DEGREE, metadata.getName());
        assertEquals(AttributeType.META, metadata.getType());
        assertEquals("degree", contentOf(metadata).get(0).getReference());
        assertEquals(1024, contentOf(metadata).get(0).getData());
    }

    @Test
    void rsaCipherAttributeNamesAreTheWireContract() {
        // Sent by the platform on cipher operations; they have no connector-side definition.
        assertEquals("data_rsaEncScheme", RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME);
        assertEquals("data_rsaOaepHash", RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME);
        assertEquals("data_rsaOaepMgf", RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME);
    }

    private static List<String> names(List<BaseAttribute> attributes) {
        return attributes.stream().map(BaseAttribute::getName).toList();
    }

    @SuppressWarnings("unchecked")
    private static List<BaseAttributeContentV2<?>> contentOf(MetadataAttribute metadata) {
        return assertInstanceOf(List.class, metadata.getContent());
    }
}
