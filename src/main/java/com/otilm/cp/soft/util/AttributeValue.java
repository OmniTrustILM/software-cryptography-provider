package com.otilm.cp.soft.util;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.core.util.AttributeDefinitionUtils;
import java.util.List;

/**
 * Reads what a request states in an attribute, reading each link of the way to it once.
 *
 * <p>
 * An attribute a request never sent is answered with an empty content rather than with nothing, so the value has to be
 * reached through that content and every link on the way can be absent. Reading a link twice, once to check it and once
 * to return it, leaves the value that was checked and the value that was returned as two separate reads; taking each
 * once is what makes a check cover what the caller receives.
 * </p>
 *
 * <p>
 * What is absent is answered as nothing, so what to do about it belongs to the caller: the two generations of the
 * interfaces report a request they cannot read in their own way, and every caller here requires the value it asked for.
 * </p>
 */
public final class AttributeValue {

    private AttributeValue() {
    }

    /**
     * The text an attribute states.
     *
     * @param attributeName the attribute to read
     * @param attributes what the request carried
     * @return the text, or {@code null} where the request states none
     */
    public static String string(String attributeName, List<RequestAttribute> attributes) {
        StringAttributeContentV2 content = AttributeDefinitionUtils
                .getSingleItemAttributeContentValue(attributeName, attributes, StringAttributeContentV2.class);
        return content == null ? null : content.getData();
    }

    /**
     * The secret an attribute states, which is one link further in than text.
     *
     * @param attributeName the attribute to read
     * @param attributes what the request carried
     * @return the secret, or {@code null} where the request states none
     */
    public static String secret(String attributeName, List<RequestAttribute> attributes) {
        SecretAttributeContentV2 content = AttributeDefinitionUtils
                .getSingleItemAttributeContentValue(attributeName, attributes, SecretAttributeContentV2.class);
        SecretAttributeContentData data = content == null ? null : content.getData();
        return data == null ? null : data.getSecret();
    }
}
