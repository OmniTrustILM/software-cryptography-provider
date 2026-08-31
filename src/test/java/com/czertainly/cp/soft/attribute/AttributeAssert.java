package com.czertainly.cp.soft.attribute;

import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.DataAttributeV2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Shared assertions for attribute definitions. The identity of an attribute, its UUID and
 * name, is what the platform stores against an instance configuration, so every definition
 * test pins those together with the content type the platform renders.
 */
final class AttributeAssert {

    private AttributeAssert() {
    }

    static DataAttributeV2 assertDataAttribute(BaseAttribute attribute, String uuid, String name,
                                               AttributeContentType contentType, String label) {
        DataAttributeV2 data = assertInstanceOf(DataAttributeV2.class, attribute,
                name + " must be a data attribute");
        assertEquals(uuid, data.getUuid(), name + " changed UUID, which orphans existing configuration");
        assertEquals(name, data.getName(), "attribute name changed, which orphans existing configuration");
        assertEquals(AttributeType.DATA, data.getType());
        assertEquals(contentType, data.getContentType(), name + " content type changed");
        assertNotNull(data.getProperties(), name + " has no properties");
        assertEquals(label, data.getProperties().getLabel(), name + " label changed");
        return data;
    }

    static void assertSelectionList(DataAttributeV2 attribute, boolean required) {
        assertNotNull(attribute.getContent(), attribute.getName() + " offers no options to select from");
        assertEquals(required, attribute.getProperties().isRequired(), attribute.getName() + " required flag changed");
        assertTrue(attribute.getProperties().isList(), attribute.getName() + " must render as a list");
        assertFalse(attribute.getProperties().isMultiSelect(),
                attribute.getName() + " must not allow multiple selections");
    }
}
