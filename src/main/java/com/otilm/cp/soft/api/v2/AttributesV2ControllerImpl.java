package com.otilm.cp.soft.api.v2;

import com.otilm.api.interfaces.connector.common.v2.AttributesController;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackRequestDto;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackResponseDto;
import com.otilm.api.model.client.connector.v2.attribute.AttributeDefinitionsDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.exception.ResourceMissingException;
import com.otilm.cp.soft.service.AttributeDefinitionRegistry;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.boot.info.BuildProperties;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves the V2 attributes interface.
 *
 * <p>
 * The definitions are published as a whole so the platform can cache them and tell when a connector build changed them,
 * which is what the connector version alongside them is for. This connector resolves no attribute content at runtime,
 * so it has no callback to answer.
 * </p>
 */
@RestController
public class AttributesV2ControllerImpl implements AttributesController {

    private final BuildProperties buildProperties;

    public AttributesV2ControllerImpl(BuildProperties buildProperties) {
        this.buildProperties = buildProperties;
    }

    @Override
    public AttributeDefinitionsDto listDefinitions(List<UUID> uuids) {
        List<BaseAttribute> published = AttributeDefinitionRegistry.definitions();
        if (uuids != null && !uuids.isEmpty()) {
            Set<String> wanted = uuids.stream().map(UUID::toString).collect(Collectors.toSet());
            published = published.stream().filter(attribute -> wanted.contains(attribute.getUuid())).toList();
        }

        AttributeDefinitionsDto definitions = new AttributeDefinitionsDto();
        definitions.setConnectorVersion(buildProperties.getVersion());
        definitions.setDefinitions(published);
        return definitions;
    }

    @Override
    public BaseAttribute getDefinition(UUID uuid) {
        return AttributeDefinitionRegistry
                .definition(uuid.toString())
                .orElseThrow(() -> new ResourceMissingException("This connector publishes no such attribute"));
    }

    @Override
    public AttributeCallbackResponseDto callback(AttributeCallbackRequestDto request) {
        throw new NotSupportedException("This connector publishes no attribute that is resolved by a callback.");
    }
}
