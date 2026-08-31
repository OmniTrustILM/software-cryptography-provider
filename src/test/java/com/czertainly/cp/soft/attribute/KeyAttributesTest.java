package com.czertainly.cp.soft.attribute;

import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.MetadataAttribute;
import com.czertainly.api.model.common.attribute.common.callback.AttributeCallback;
import com.czertainly.api.model.common.attribute.common.callback.AttributeCallbackMapping;
import com.czertainly.api.model.common.attribute.common.callback.AttributeValueTarget;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.DataAttributeV2;
import com.czertainly.api.model.common.attribute.v2.GroupAttributeV2;
import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.czertainly.cp.soft.attribute.AttributeAssert.assertDataAttribute;
import static com.czertainly.cp.soft.attribute.AttributeAssert.assertSelectionList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyAttributesTest {

    @Test
    void keyAliasIsSuppliedByTheClient() {
        DataAttributeV2 attribute = assertDataAttribute(
                KeyAttributes.buildDataKeyAlias(),
                KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS_UUID,
                KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS,
                AttributeContentType.STRING,
                KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS_LABEL);

        assertTrue(attribute.getProperties().isRequired());
        assertFalse(attribute.getProperties().isList(), "the alias is free text, not a selection");
        assertNull(attribute.getContent(), "the alias is provided by the client, not offered by the connector");
    }

    @Test
    void keyAlgorithmOffersEverySupportedAlgorithmByCode() {
        DataAttributeV2 attribute = assertDataAttribute(
                KeyAttributes.buildDataKeyAlgorithmSelect(),
                KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM_UUID,
                KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM,
                AttributeContentType.STRING,
                KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM_LABEL);
        assertSelectionList(attribute, true);

        assertEquals(KeyAlgorithm.values().length, attribute.getContent().size());
        // The reference is the label and the data is the code; the key specification
        // callback is keyed on the reference, so both halves matter.
        assertEquals(List.of(KeyAlgorithm.values()).stream().map(KeyAlgorithm::getLabel).toList(),
                attribute.getContent().stream().map(BaseAttributeContentV2::getReference).toList());
        assertEquals(List.of(KeyAlgorithm.values()).stream().map(KeyAlgorithm::getCode).toList(),
                attribute.getContent().stream().map(BaseAttributeContentV2::getData).toList());
    }

    @Test
    void keySpecificationGroupCallsBackWithTheSelectedAlgorithm() {
        GroupAttributeV2 group = assertInstanceOf(GroupAttributeV2.class,
                KeyAttributes.buildGroupKeyAttributesBasedOnSelectedAlgorithm());
        assertEquals(KeyAttributes.ATTRIBUTE_GROUP_KEY_SPEC_UUID, group.getUuid());
        assertEquals(KeyAttributes.ATTRIBUTE_GROUP_KEY_SPEC, group.getName());
        assertEquals(AttributeType.GROUP, group.getType());

        AttributeCallback callback = group.getAttributeCallback();
        assertNotNull(callback);
        assertEquals("/v1/cryptographyProvider/callbacks/keyspec/{algorithm}/attributes",
                callback.getCallbackContext());
        assertEquals("GET", callback.getCallbackMethod());

        assertEquals(1, callback.getMappings().size());
        AttributeCallbackMapping mapping = callback.getMappings().iterator().next();
        // Mapped from the reference rather than the data, so the callback receives the
        // algorithm label used to select the specification attributes.
        assertEquals(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM + ".reference", mapping.getFrom());
        assertEquals("algorithm", mapping.getTo());
        assertEquals(AttributeValueTarget.PATH_VARIABLE, mapping.getTargets().iterator().next());
    }

    @Test
    void aliasMetadataRecordsTheAliasUsedInTheKeystore() {
        MetadataAttribute metadata = KeyAttributes.buildAliasMetadata("my-key");
        assertEquals(KeyAttributes.ATTRIBUTE_META_KEY_ALIAS_UUID, metadata.getUuid());
        assertEquals(KeyAttributes.ATTRIBUTE_META_KEY_ALIAS, metadata.getName());
        assertEquals(AttributeType.META, metadata.getType());

        List<?> content = assertInstanceOf(List.class, metadata.getContent());
        BaseAttributeContentV2<?> entry = assertInstanceOf(BaseAttributeContentV2.class, content.get(0));
        assertEquals("alias", entry.getReference());
        assertEquals("my-key", entry.getData());
    }
}
