package com.otilm.cp.soft.attribute;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallbackMapping;
import com.otilm.api.model.common.attribute.common.callback.AttributeValueTarget;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.GroupAttributeV2;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

public class KeyAttributes {

    private KeyAttributes() {
    }

    // Cryptographic Key Attributes

    public static final String ATTRIBUTE_DATA_KEY_ALIAS = "data_keyAlias";
    public static final String ATTRIBUTE_DATA_KEY_ALIAS_UUID = "61a228de-c54e-461e-b0d7-ad156a547b51";
    public static final String ATTRIBUTE_DATA_KEY_ALIAS_LABEL = "Cryptographic Key Alias";
    public static final String ATTRIBUTE_DATA_KEY_ALIAS_DESCRIPTION = "Alias for the Key that should be unique within the Token";

    public static final String ATTRIBUTE_DATA_KEY_ALGORITHM = "data_keyAlgorithm";
    public static final String ATTRIBUTE_DATA_KEY_ALGORITHM_UUID = "72159c04-d1a9-4703-8b23-469224425d5f";
    public static final String ATTRIBUTE_DATA_KEY_ALGORITHM_LABEL = "Cryptographic Key Algorithm";
    public static final String ATTRIBUTE_DATA_KEY_ALGORITHM_DESCRIPTION = "Select one of the supported cryptographic key algorithms";

    public static final String ATTRIBUTE_GROUP_KEY_SPEC = "group_keySpec";
    public static final String ATTRIBUTE_GROUP_KEY_SPEC_UUID = "dfcfb71f-a161-4aa7-8b1f-726b477b3492";
    public static final String ATTRIBUTE_GROUP_KEY_SPEC_LABEL = "Cryptographic Key Specification";

    // Cryptographic Key METADATA

    public static final String ATTRIBUTE_META_KEY_REFERENCE = "meta_keyReference";
    public static final String ATTRIBUTE_META_KEY_REFERENCE_UUID = "2f0d1d3a-7c65-4f6f-9d3c-8c19b2f1f9a4";
    public static final String ATTRIBUTE_META_KEY_REFERENCE_LABEL = "Key Reference";
    public static final String ATTRIBUTE_META_KEY_REFERENCE_DESCRIPTION = "Durable reference of the Key in the provider";

    public static final String ATTRIBUTE_META_KEY_ALIAS = "meta_keyAlias";
    public static final String ATTRIBUTE_META_KEY_ALIAS_UUID = "a5575bb8-dd88-4b60-bb73-75b862da78aa";
    public static final String ATTRIBUTE_META_KEY_ALIAS_LABEL = "Key Alias";
    public static final String ATTRIBUTE_META_KEY_ALIAS_DESCRIPTION = "Alias of the Key";

    public static BaseAttribute buildDataKeyAlias() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_KEY_ALIAS_UUID);
        attribute.setName(ATTRIBUTE_DATA_KEY_ALIAS);
        attribute.setDescription(ATTRIBUTE_DATA_KEY_ALIAS_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_KEY_ALIAS_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(false);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // content provided by client

        return attribute;
    }

    public static BaseAttribute buildDataKeyAlgorithmSelect() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_KEY_ALGORITHM_UUID);
        attribute.setName(ATTRIBUTE_DATA_KEY_ALGORITHM);
        attribute.setDescription(ATTRIBUTE_DATA_KEY_ALGORITHM_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_KEY_ALGORITHM_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute
                .setContent(Stream
                        .of(KeyAlgorithm.values())
                        .map(item -> new StringAttributeContentV2(item.getLabel(), item.getCode()))
                        .toList());

        return attribute;
    }

    public static BaseAttribute buildGroupKeyAttributesBasedOnSelectedAlgorithm() {
        // define Group Attribute
        GroupAttributeV2 attribute = new GroupAttributeV2();
        attribute.setUuid(ATTRIBUTE_GROUP_KEY_SPEC_UUID);
        attribute.setName(ATTRIBUTE_GROUP_KEY_SPEC);
        attribute.setType(AttributeType.GROUP);
        attribute.setDescription(ATTRIBUTE_GROUP_KEY_SPEC_LABEL);
        // prepare mappings for callback
        Set<AttributeCallbackMapping> mappings = new HashSet<>();
        mappings
                .add(new AttributeCallbackMapping(ATTRIBUTE_DATA_KEY_ALGORITHM + ".reference", "algorithm",
                        AttributeValueTarget.PATH_VARIABLE));
        // create attribute callback
        AttributeCallback attributeCallback = new AttributeCallback();
        attributeCallback.setCallbackContext("/v1/cryptographyProvider/callbacks/keyspec/{algorithm}/attributes");
        attributeCallback.setCallbackMethod("GET");
        attributeCallback.setMappings(mappings);
        // set attribute callback
        attribute.setAttributeCallback(attributeCallback);

        return attribute;
    }

    // METADATA

    /**
     * The metadata naming a key durably.
     *
     * <p>
     * The V2 interfaces address a key by the metadata the connector published for it, and require that metadata to keep
     * identifying the same key across restarts. The row's own reference does that, where the alias alone would not
     * distinguish the two halves of a key pair.
     * </p>
     *
     * @param reference the durable reference of the key
     * @return the key reference metadata attribute
     */
    public static MetadataAttribute buildKeyReferenceMetadata(String reference) {
        MetadataAttributeV2 metadataAttribute = new MetadataAttributeV2();
        metadataAttribute.setUuid(ATTRIBUTE_META_KEY_REFERENCE_UUID);
        metadataAttribute.setName(ATTRIBUTE_META_KEY_REFERENCE);
        metadataAttribute.setType(AttributeType.META);
        metadataAttribute.setContentType(AttributeContentType.STRING);
        metadataAttribute.setDescription(ATTRIBUTE_META_KEY_REFERENCE_DESCRIPTION);

        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel(ATTRIBUTE_META_KEY_REFERENCE_LABEL);
        properties.setVisible(true);
        properties.setGlobal(false);
        metadataAttribute.setProperties(properties);

        StringAttributeContentV2 content = new StringAttributeContentV2();
        content.setReference("keyReference");
        content.setData(reference);
        metadataAttribute.setContent(List.of(content));

        return metadataAttribute;
    }

    public static MetadataAttribute buildAliasMetadata(String alias) {
        // define Metadata Attribute
        MetadataAttributeV2 metadataAttribute = new MetadataAttributeV2();
        metadataAttribute.setUuid(ATTRIBUTE_META_KEY_ALIAS_UUID);
        metadataAttribute.setName(ATTRIBUTE_META_KEY_ALIAS);
        metadataAttribute.setType(AttributeType.META);
        metadataAttribute.setContentType(AttributeContentType.STRING);
        metadataAttribute.setDescription(ATTRIBUTE_META_KEY_ALIAS_DESCRIPTION);
        // create properties
        MetadataAttributeProperties metadataAttributeProperties = new MetadataAttributeProperties();
        metadataAttributeProperties.setLabel(ATTRIBUTE_META_KEY_ALIAS_LABEL);
        metadataAttributeProperties.setVisible(true);
        metadataAttributeProperties.setGlobal(false);
        metadataAttribute.setProperties(metadataAttributeProperties);
        // create StringAttributeContent
        StringAttributeContentV2 stringAttributeContent = new StringAttributeContentV2();
        stringAttributeContent.setReference("alias");
        stringAttributeContent.setData(alias);
        metadataAttribute.setContent(List.of(stringAttributeContent));

        return metadataAttribute;
    }

}
