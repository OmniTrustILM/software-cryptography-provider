package com.otilm.cp.soft.service;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * What this connector publishes as its attribute definitions.
 *
 * <p>
 * The platform tells attributes apart by their identifier and asks for them by it, so a definition without one, or two
 * different definitions sharing one, is a mistake that ships: the platform would resolve one of them to the other. The
 * definitions are a fixed list assembled from the classes the operations use, which is exactly the kind of list that
 * goes wrong when a new attribute is added by copying an old one.
 * </p>
 */
class AttributeDefinitionRegistryTest {

    @Test
    void publishesSomethingForEveryOperationToAskFor() {
        // given
        // when
        List<BaseAttribute> published = AttributeDefinitionRegistry.definitions();

        // then
        assertFalse(published.isEmpty(), "the attributes interface has to have something to publish");
    }

    @Test
    void namesAndIdentifiesEveryDefinitionItPublishes() {
        // given
        // when
        // then
        for (BaseAttribute attribute : AttributeDefinitionRegistry.definitions()) {
            assertNotNull(attribute.getUuid(), () -> "an attribute is published without an identifier");
            assertNotNull(attribute.getName(), () -> attribute.getUuid() + " is published without a name");
        }
    }

    @Test
    void publishesOneDefinitionPerIdentifier() {
        // given
        Map<String, String> byUuid = new HashMap<>();

        // when
        // then
        for (BaseAttribute attribute : AttributeDefinitionRegistry.definitions()) {
            String taken = byUuid.put(attribute.getUuid(), attribute.getName());
            assertNull(taken, () -> "both " + taken + " and " + attribute.getName() + " are published under "
                    + attribute.getUuid());
        }
    }

}
