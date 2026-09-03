package com.otilm.cp.soft.testsupport;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.cp.soft.attribute.TokenInstanceAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Token contexts as the V2 interfaces carry them, for the tests that need one.
 *
 * <p>
 * Every V2 request identifies its token through these attributes, so the tests build them the same way rather than each
 * assembling its own: a context that drifts from what the platform sends would test nothing.
 * </p>
 */
public final class TokenContextFixtures {

    /** The code the fixtures open their keystores with. */
    public static final String CODE = "00000000";

    private TokenContextFixtures() {
    }

    /** A context asking for a token of the given name, which is created the first time it is used. */
    public static List<RequestAttribute> newToken(String name) {
        return newToken(name, CODE);
    }

    /** A context asking for a token of the given name, opened with the given code. */
    public static List<RequestAttribute> newToken(String name, String code) {
        List<RequestAttribute> attributes = new ArrayList<>();
        attributes.add(string(TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION, "new"));
        attributes.add(string(TokenInstanceAttributes.ATTRIBUTE_DATA_NEW_TOKEN_NAME, name));
        attributes.add(secret(TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE, code));
        return attributes;
    }

    /** A context selecting a token that already exists. */
    public static List<RequestAttribute> existingToken(UUID uuid, String name, String code) {
        List<RequestAttribute> attributes = new ArrayList<>();
        attributes.add(string(TokenInstanceAttributes.ATTRIBUTE_DATA_CREATE_TOKEN_ACTION, "existing"));
        RequestAttributeV2 selected = new RequestAttributeV2();
        selected.setName(TokenInstanceAttributes.ATTRIBUTE_DATA_SELECT_EXISTING_TOKEN);
        selected.setContent(List.of(new StringAttributeContentV2(name, uuid.toString())));
        attributes.add(selected);
        attributes.add(secret(TokenInstanceAttributes.ATTRIBUTE_DATA_TOKEN_CODE, code));
        return attributes;
    }

    /** A unique token name, so tests sharing the database never collide. */
    public static String uniqueName(String prefix) {
        return prefix + "-" + UUID.randomUUID();
    }

    public static RequestAttribute string(String name, String value) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(new StringAttributeContentV2(value, value)));
        return attribute;
    }

    public static RequestAttribute secret(String name, String value) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(new SecretAttributeContentV2(name, new SecretAttributeContentData(value))));
        return attribute;
    }
}
