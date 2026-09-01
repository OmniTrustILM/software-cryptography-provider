package com.otilm.cp.soft.attribute;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.cp.soft.collection.EcdsaCurveName;

import java.util.List;

public class EcdsaKeyAttributes {

    private EcdsaKeyAttributes() {
    }

    public static final String ATTRIBUTE_DATA_ECDSA_CURVE = "data_ecdsaCurve";
    public static final String ATTRIBUTE_DATA_ECDSA_CURVE_UUID = "08730b36-90f3-4046-9f13-3cf827ad6cc7";
    public static final String ATTRIBUTE_DATA_ECDSA_CURVE_LABEL = "Named Curve";
    public static final String ATTRIBUTE_DATA_ECDSA_CURVE_DESCRIPTION = "Select one of the supported named curves";

    // ECDSA signature Attributes

    public static final String ATTRIBUTE_DATA_SIG_DIGEST = "data_sigDigest";

    public static List<BaseAttribute> getEcdsaKeySpecAttributes() {
        return List.of(
                buildDataEscdaNamedCurves()
        );
    }

    public static BaseAttribute buildDataEscdaNamedCurves() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_ECDSA_CURVE_UUID);
        attribute.setName(ATTRIBUTE_DATA_ECDSA_CURVE);
        attribute.setDescription(ATTRIBUTE_DATA_ECDSA_CURVE_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_ECDSA_CURVE_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(EcdsaCurveName.asStringAttributeContentList());

        return attribute;
    }
}
