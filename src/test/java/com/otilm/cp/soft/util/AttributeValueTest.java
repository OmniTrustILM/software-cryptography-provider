package com.otilm.cp.soft.util;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * An attribute a request never sent is answered with an empty content rather than with nothing, so every link on the
 * way to a value can be absent. What is absent has to read as nothing, since a caller that takes it for a value
 * dereferences nothing.
 */
class AttributeValueTest {

    private static final String NAME = "data_thing";

    @Test
    void readsTheTextAnAttributeStates() {
        // given
        List<RequestAttribute> attributes = List.of(text(NAME, "what it says"));

        // when
        // then
        assertEquals("what it says", AttributeValue.string(NAME, attributes));
    }

    @Test
    void readsNoTextFromAnAttributeTheRequestNeverSent() {
        // given
        List<RequestAttribute> attributes = List.of(text("data_something_else", "beside the point"));

        // when
        // then
        assertNull(AttributeValue.string(NAME, attributes));
    }

    @Test
    void readsNoTextFromAnAttributeThatStatesNone() {
        // given
        RequestAttributeV2 empty = new RequestAttributeV2();
        empty.setName(NAME);
        empty.setContent(List.of(new StringAttributeContentV2()));

        // when
        // then
        assertNull(AttributeValue.string(NAME, List.of(empty)));
    }

    @Test
    void readsTheSecretAnAttributeStates() {
        // given
        List<RequestAttribute> attributes = List.of(secret(NAME, new SecretAttributeContentData("the code")));

        // when
        // then
        assertEquals("the code", AttributeValue.secret(NAME, attributes));
    }

    @Test
    void readsNoSecretFromAnAttributeTheRequestNeverSent() {
        // given
        // when
        // then
        assertNull(AttributeValue.secret(NAME, List.of()));
    }

    /** The content is there and the data behind it is not, which is the shape an unsent attribute comes back as. */
    @Test
    void readsNoSecretFromAContentCarryingNoData() {
        // given
        List<RequestAttribute> attributes = List.of(secret(NAME, null));

        // when
        // then
        assertNull(AttributeValue.secret(NAME, attributes));
    }

    @Test
    void readsNoSecretFromDataCarryingNone() {
        // given
        List<RequestAttribute> attributes = List.of(secret(NAME, new SecretAttributeContentData(null)));

        // when
        // then
        assertNull(AttributeValue.secret(NAME, attributes));
    }

    private static RequestAttribute text(String name, String value) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(new StringAttributeContentV2(value, value)));
        return attribute;
    }

    private static RequestAttribute secret(String name, SecretAttributeContentData data) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(new SecretAttributeContentV2(name, data)));
        return attribute;
    }
}
