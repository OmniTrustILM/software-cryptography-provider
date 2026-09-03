package com.otilm.cp.soft.util;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import java.util.List;

/**
 * Metadata a token instance carries, shared by the interfaces that create one.
 *
 * <p>
 * The attribute UUID and name identify the metadata in the platform database, so both the V1 and V2 paths must write
 * exactly the same ones: a token created through either must look the same to whatever reads it afterwards.
 * </p>
 */
public final class TokenMetadataUtil {

    private static final String NAME_ATTRIBUTE_UUID = "81d8c383-e499-4914-b6de-d92139bfe742";

    private static final String NAME_ATTRIBUTE_NAME = "meta_tokenName";

    private TokenMetadataUtil() {
    }

    /**
     * The metadata naming a token instance.
     *
     * @param name the token instance name
     * @return the name metadata attribute
     */
    public static MetadataAttribute nameMetadata(String name) {
        MetadataAttributeV2 metadataAttribute = new MetadataAttributeV2();
        metadataAttribute.setUuid(NAME_ATTRIBUTE_UUID);
        metadataAttribute.setName(NAME_ATTRIBUTE_NAME);
        metadataAttribute.setType(AttributeType.META);
        metadataAttribute.setContentType(AttributeContentType.STRING);
        metadataAttribute.setDescription("Reference name of the Token instance");

        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel("Token instance name");
        properties.setVisible(true);
        properties.setGlobal(false);
        metadataAttribute.setProperties(properties);

        StringAttributeContentV2 content = new StringAttributeContentV2();
        content.setReference("tokenName");
        content.setData(name);
        metadataAttribute.setContent(List.of(content));

        return metadataAttribute;
    }
}
