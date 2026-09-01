package com.otilm.cp.soft.attribute;

import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import org.junit.jupiter.api.Test;

import static com.otilm.cp.soft.attribute.AttributeAssert.assertDataAttribute;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenInstanceActivationAttributesTest {

    @Test
    void activationCodeIsCarriedAsASecret() {
        DataAttributeV2 attribute = assertDataAttribute(
                TokenInstanceActivationAttributes.buildDataTokenActivationCode(),
                TokenInstanceActivationAttributes.ATTRIBUTE_DATA_ACTIVATION_CODE_UUID,
                TokenInstanceActivationAttributes.ATTRIBUTE_DATA_ACTIVATION_CODE, AttributeContentType.SECRET,
                TokenInstanceActivationAttributes.ATTRIBUTE_DATA_ACTIVATION_CODE_LABEL);

        // This attribute carries the keystore password on every activation. Any content type
        // other than SECRET would have the platform store and render it in the clear.
        assertTrue(attribute.getProperties().isRequired());
        assertTrue(attribute.getProperties().isVisible());
        assertFalse(attribute.getProperties().isReadOnly());
        assertNull(attribute.getContent(), "no activation code may be baked into the definition");
    }

    @Test
    void activationCodeIsDistinctFromTheCreationTimeCode() {
        // Activation and creation use separate attributes with separate identifiers; reusing
        // one for the other would silently rebind existing token configuration.
        assertNotEquals(TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE_UUID,
                TokenInstanceActivationAttributes.ATTRIBUTE_DATA_ACTIVATION_CODE_UUID,
                "activation and creation codes must keep distinct UUIDs");
        assertNotEquals(TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE,
                TokenInstanceActivationAttributes.ATTRIBUTE_DATA_ACTIVATION_CODE,
                "activation and creation codes must keep distinct names");
    }
}
