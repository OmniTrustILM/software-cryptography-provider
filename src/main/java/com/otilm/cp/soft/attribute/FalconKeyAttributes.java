package com.otilm.cp.soft.attribute;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.cp.soft.collection.FalconDegree;

import java.util.List;

public class FalconKeyAttributes {

    private FalconKeyAttributes() {
    }

    // Falcon Attributes
    public static final String ATTRIBUTE_DATA_FALCON_DEGREE = "data_falconDegree";
    public static final String ATTRIBUTE_DATA_FALCON_DEGREE_UUID = "d4d86b9a-b5df-4a1b-8d9d-1671cfb4b496";
    public static final String ATTRIBUTE_DATA_FALCON_DEGREE_LABEL = "Falcon Key Degree";
    public static final String ATTRIBUTE_DATA_FALCON_DEGREE_DESCRIPTION = "Degree (n) of the Falcon Key";

    public static final String ATTRIBUTE_META_FALCON_DEGREE = "meta_falconDegree";
    public static final String ATTRIBUTE_META_FALCON_DEGREE_UUID = "bd9b2826-f7fc-4bc3-b817-66bc231f1ee2";
    public static final String ATTRIBUTE_META_FALCON_DEGREE_LABEL = "Falcon Key Degree";
    public static final String ATTRIBUTE_META_FALCON_DEGREE_DESCRIPTION = "Degree (n) of the Falcon Key";

    public static List<BaseAttribute> getFalconKeySpecAttributes() {
        return List.of(
                buildDataFalconDegree()
        );
    }

    public static BaseAttribute buildDataFalconDegree() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_FALCON_DEGREE_UUID);
        attribute.setName(ATTRIBUTE_DATA_FALCON_DEGREE);
        attribute.setDescription(ATTRIBUTE_DATA_FALCON_DEGREE_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.INTEGER);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_FALCON_DEGREE_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(FalconDegree.asIntegerAttributeContentList());

        return attribute;
    }

    public static MetadataAttribute buildFalconDegreeMetadata(int degree) {
        // define Metadata Attribute
        MetadataAttributeV2 metadataAttribute = new MetadataAttributeV2();
        metadataAttribute.setUuid(ATTRIBUTE_META_FALCON_DEGREE_UUID);
        metadataAttribute.setName(ATTRIBUTE_META_FALCON_DEGREE);
        metadataAttribute.setType(AttributeType.META);
        metadataAttribute.setContentType(AttributeContentType.STRING);
        metadataAttribute.setDescription(ATTRIBUTE_META_FALCON_DEGREE_DESCRIPTION);
        // create properties
        MetadataAttributeProperties metadataAttributeProperties = new MetadataAttributeProperties();
        metadataAttributeProperties.setLabel(ATTRIBUTE_META_FALCON_DEGREE_LABEL);
        metadataAttributeProperties.setVisible(true);
        metadataAttributeProperties.setGlobal(false);
        metadataAttribute.setProperties(metadataAttributeProperties);
        // create IntegerAttributeContent
        IntegerAttributeContentV2 integerAttributeContent = new IntegerAttributeContentV2();
        integerAttributeContent.setReference("degree");
        integerAttributeContent.setData(degree);
        metadataAttribute.setContent(List.of(integerAttributeContent));

        return metadataAttribute;
    }

}
