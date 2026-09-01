package com.otilm.cp.soft.attribute;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;

public class TokenInstanceActivationAttributes {

    private TokenInstanceActivationAttributes() {
    }

    // Token instance activation Attributes

    public static final String ATTRIBUTE_DATA_ACTIVATION_CODE = "data_tokenActivationCode";
    public static final String ATTRIBUTE_DATA_ACTIVATION_CODE_UUID = "0d4044f0-2af0-4f10-ac09-319072eb3393";
    public static final String ATTRIBUTE_DATA_ACTIVATION_CODE_LABEL = "Token activation code";
    public static final String ATTRIBUTE_DATA_ACTIVATION_CODE_DESCRIPTION = "Activation code that will be used to activate this Token";

    public static BaseAttribute buildDataTokenActivationCode() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_ACTIVATION_CODE_UUID);
        attribute.setName(ATTRIBUTE_DATA_ACTIVATION_CODE);
        attribute.setDescription(ATTRIBUTE_DATA_ACTIVATION_CODE_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.SECRET);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_ACTIVATION_CODE_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(false);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);

        return attribute;
    }
}
