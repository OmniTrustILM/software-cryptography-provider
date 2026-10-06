package com.otilm.cp.soft.util;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import java.util.List;
import java.util.Objects;

/**
 * Builds request attributes with typed V2 content.
 */
public final class RequestAttributes {

    private RequestAttributes() {
    }

    /**
     * Creates a single string value with the same text as its display reference.
     *
     * @param name the attribute name; must not be null
     * @param value the string value; must not be null
     * @return the request attribute containing the value
     */
    public static RequestAttribute string(String name, String value) {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(value, "value must not be null");
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(new StringAttributeContentV2(value, value)));
        return attribute;
    }
}
