package com.otilm.cp.soft.api.v2;

import com.otilm.api.interfaces.connector.common.v2.AttributesController;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackRequestDto;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackResponseDto;
import com.otilm.api.model.client.connector.v2.attribute.AttributeDefinitionsDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.attribute.KeySpecV2Attributes;
import com.otilm.cp.soft.exception.AttributeDefinitionMissingException;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.service.AttributeDefinitionRegistry;
import com.otilm.cp.soft.util.AttributeValue;
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
 * which is what the connector version alongside them is for. The one attribute resolved at runtime is the key
 * specification, whose parameters depend on the key algorithm a creation chose.
 * </p>
 */
@RestController
public class AttributesV2ControllerImpl implements AttributesController {

    private final BuildProperties buildProperties;

    private final List<BaseAttribute> published;

    public AttributesV2ControllerImpl(BuildProperties buildProperties) {
        this.buildProperties = buildProperties;
        // Assembled as the connector starts, since they are the same for every request and a set of definitions that
        // cannot be published has to stop it from starting rather than fail whoever asks for them first.
        this.published = AttributeDefinitionRegistry.definitions();
    }

    @Override
    public AttributeDefinitionsDto listDefinitions(List<UUID> uuids) {
        List<BaseAttribute> answered = published;
        if (uuids != null && !uuids.isEmpty()) {
            Set<String> wanted = uuids.stream().map(UUID::toString).collect(Collectors.toSet());
            answered = answered.stream().filter(attribute -> wanted.contains(attribute.getUuid())).toList();
        }

        AttributeDefinitionsDto definitions = new AttributeDefinitionsDto();
        definitions.setConnectorVersion(buildProperties.getVersion());
        definitions.setDefinitions(answered);
        return definitions;
    }

    @Override
    public BaseAttribute getDefinition(UUID uuid) {
        return published
                .stream()
                .filter(attribute -> uuid.toString().equals(attribute.getUuid()))
                .findFirst()
                .orElseThrow(
                        () -> new AttributeDefinitionMissingException("This connector publishes no such attribute"));
    }

    @Override
    public AttributeCallbackResponseDto callback(AttributeCallbackRequestDto request) {
        BaseAttribute attribute = getDefinition(request.getAttributeUuid());
        if (!KeySpecV2Attributes.ATTRIBUTE_GROUP_KEY_SPEC_UUID.equals(attribute.getUuid())) {
            throw new NotSupportedException("This attribute is not resolved by a callback.");
        }
        String algorithm = AttributeValue
                .string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, request.getCurrentAttributes());

        AttributeCallbackResponseDto response = new AttributeCallbackResponseDto();
        response
                .setAttributes(algorithm == null
                        ? List.of()
                        : KeySpecV2Attributes.forAlgorithm(KeyAlgorithm.findByCode(algorithm)));
        return response;
    }
}
