package com.otilm.cp.soft.attribute;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.cp.soft.collection.MLDSASecurityCategory;

import java.util.List;

public class MLDSAKeyAttributes {

    private MLDSAKeyAttributes() {

    }

    public static final String ATTRIBUTE_DATA_MLDSA_LEVEL = "data_mldsaLevel";
    public static final String ATTRIBUTE_DATA_MLDSA_LEVEL_UUID = "22e317d6-dd78-4968-9a26-c1823a4fb2e6";
    public static final String ATTRIBUTE_DATA_MLDSA_LEVEL_LABEL = "NIST Security Category";
    public static final String ATTRIBUTE_DATA_MLDSA_LEVEL_DESCRIPTION = "Security strength according NIST definition";

    public static final String ATTRIBUTE_DATA_MLDSA_PREHASH = "data_mldsaPrehash";
    public static final String ATTRIBUTE_DATA_MLDSA_PREHASH_UUID = "dd1a8f25-a529-42a6-9c3d-3b9a70fc7e9b";
    public static final String ATTRIBUTE_DATA_MLDSA_PREHASH_LABEL = "For Pre-Hash use";
    public static final String ATTRIBUTE_DATA_MLDSA_PREHASH_DESCRIPTION = "When checked, the key will be intended for SHA-512 pre-hash of the signature, otherwise it is intended for the pure version of algorithm";

    public static DataAttribute buildBooleanPreHash() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_MLDSA_PREHASH_UUID);
        attribute.setName(ATTRIBUTE_DATA_MLDSA_PREHASH);
        attribute.setDescription(ATTRIBUTE_DATA_MLDSA_PREHASH_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.BOOLEAN);

        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_MLDSA_PREHASH_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(false);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);

        // Set content
        attribute.setContent(List.of(new BooleanAttributeContentV2(false)));

        return attribute;
    }

    public static List<BaseAttribute> getMldsaKeySpecAttributes() {
        return List.of(buildDataMLDSASecurityCategory(), buildBooleanPreHash());
    }

    public static BaseAttribute buildDataMLDSASecurityCategory() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_MLDSA_LEVEL_UUID);
        attribute.setName(ATTRIBUTE_DATA_MLDSA_LEVEL);
        attribute.setDescription(ATTRIBUTE_DATA_MLDSA_LEVEL_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.INTEGER);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_MLDSA_LEVEL_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(MLDSASecurityCategory.asIntegerAttributeContentList());

        return attribute;
    }

}
