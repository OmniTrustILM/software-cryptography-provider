package com.otilm.cp.soft.attribute;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.cp.soft.collection.SLHDSAHash;
import com.otilm.cp.soft.collection.SLHDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASignatureMode;

import java.util.List;

public class SLHDSAKeyAttributes {

    private SLHDSAKeyAttributes() {
    }

    public static final String ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY = "data_slhdsaSecurityCategory";
    public static final String ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY_UUID = "b4d4cf43-d214-42e5-a402-3db66d9c1c6c";
    public static final String ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY_LABEL = "NIST Security Category";
    public static final String ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY_DESCRIPTION = "Strength of algorithm according to NIST";

    public static final String ATTRIBUTE_DATA_SLHDSA_HASH = "data_slhdsaHash";
    public static final String ATTRIBUTE_DATA_SLHDSA_HASH_UUID = "fd0dddbf-3cb5-477d-a3e2-6ebe8c1ec639";
    public static final String ATTRIBUTE_DATA_SLHDSA_HASH_LABEL = "Hash Function";
    public static final String ATTRIBUTE_DATA_SLHDSA_HASH_DESCRIPTION = "Hash function used to instantiate the signature scheme";

    public static final String ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE = "data_slhdsaSignatureMode";
    public static final String ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE_UUID = "7a33f35a-8e32-4bcc-bf3e-37654b6a8107";
    public static final String ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE_LABEL = "Signature generation mode";
    public static final String ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE_DESCRIPTION = "Create relatively small signatures or have relatively fast signature generation";

    public static final String ATTRIBUTE_DATA_SLHDSA_PREHASH = "data_slhdsaPrehash";
    public static final String ATTRIBUTE_DATA_SLHDSA_PREHASH_UUID = "81f20bdd-ec84-4a7f-9c9d-13efce16665a";
    public static final String ATTRIBUTE_DATA_SLHDSA_PREHASH_LABEL = "For Pre-Hash use";
    public static final String ATTRIBUTE_DATA_SLHDSA_PREHASH_DESCRIPTION = "When checked, pre-hash will be used for signature when signing with this key. Hash algorithm depends on other SLH-DSA parameters - SHA2 will be used when SHA2 is used in algorithm (SHA2-256 for security category 1, SHA-512 for categories 3 and 5) " +
            "and SHAKE for SHAKE used in algorithm (SHAKE128 for security category 1, SHAKE256 for categories 3 and 5)." +
            "Otherwise the pure version of algorithm will be used.";


    public static DataAttribute buildBooleanPreHash() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_SLHDSA_PREHASH_UUID);
        attribute.setName(ATTRIBUTE_DATA_SLHDSA_PREHASH);
        attribute.setDescription(ATTRIBUTE_DATA_SLHDSA_PREHASH_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.BOOLEAN);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_SLHDSA_PREHASH_LABEL);
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


    public static List<BaseAttribute> getSlhDsaKeySpecAttributes() {
        return List.of(
                buildDataSecurityCategory(),
                buildDataHash(),
                buildDataSignatureMode(),
                buildBooleanPreHash()
        );
    }

    public static BaseAttribute buildDataHash() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_SLHDSA_HASH_UUID);
        attribute.setName(ATTRIBUTE_DATA_SLHDSA_HASH);
        attribute.setDescription(ATTRIBUTE_DATA_SLHDSA_HASH_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_SLHDSA_HASH_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(SLHDSAHash.asStringAttributeContentList());

        return attribute;
    }

    public static BaseAttribute buildDataSecurityCategory() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY_UUID);
        attribute.setName(ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY);
        attribute.setDescription(ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(SLHDSASecurityCategory.asStringAttributeContentList());

        return attribute;
    }

    public static BaseAttribute buildDataSignatureMode() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE_UUID);
        attribute.setName(ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE);
        attribute.setDescription(ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE_LABEL);
        attributeProperties.setRequired(false);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(SLHDSASignatureMode.asStringAttributeContentList());

        return attribute;
    }

}
