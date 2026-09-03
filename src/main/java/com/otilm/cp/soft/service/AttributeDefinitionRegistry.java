package com.otilm.cp.soft.service;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.cp.soft.attribute.EcdsaKeyAttributes;
import com.otilm.cp.soft.attribute.FalconKeyAttributes;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.attribute.MLDSAKeyAttributes;
import com.otilm.cp.soft.attribute.MLKEMAttributes;
import com.otilm.cp.soft.attribute.OperationAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.attribute.SLHDSAKeyAttributes;
import com.otilm.cp.soft.attribute.TokenInstanceAttributes;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Every attribute definition this connector publishes, in one place.
 *
 * <p>
 * The V2 attributes interface asks for the definitions as a whole and for one at a time by its identifier, so they have
 * to be reachable without knowing which operation would ask for them. Definitions are values rather than state, so this
 * assembles them on demand from the same classes the operations use.
 * </p>
 */
public final class AttributeDefinitionRegistry {

    private AttributeDefinitionRegistry() {
    }

    /**
     * Every definition this connector publishes, each appearing once.
     *
     * @return the definitions, in a stable order
     */
    public static List<BaseAttribute> definitions() {
        Map<String, BaseAttribute> byUuid = new LinkedHashMap<>();
        all().forEach(attribute -> byUuid.putIfAbsent(attribute.getUuid(), attribute));
        return List.copyOf(byUuid.values());
    }

    /**
     * The definition with the given identifier.
     *
     * @param uuid the definition's identifier
     * @return the definition, or empty when this connector publishes no such definition
     */
    public static Optional<BaseAttribute> definition(String uuid) {
        return definitions().stream().filter(attribute -> uuid.equals(attribute.getUuid())).findFirst();
    }

    private static List<BaseAttribute> all() {
        List<BaseAttribute> attributes = new ArrayList<>(TokenInstanceAttributes.getNewTokenAttributes());
        // What a token context asks for once tokens exist: the choice between an existing token and a new one, and the
        // selection itself. Published without content, since a definition describes the attribute rather than a token.
        attributes.add(TokenInstanceAttributes.buildInitialInfo());
        attributes.add(TokenInstanceAttributes.buildOptions());
        attributes.add(TokenInstanceAttributes.buildGroupBasedOnSelect());
        attributes.add(TokenInstanceAttributes.buildDataSelectExistingToken(List.of()));
        attributes.add(KeyAttributes.buildDataKeyAlias());
        attributes.add(KeyAttributes.buildDataKeyAlgorithmSelect());
        attributes.add(KeyAttributes.buildGroupKeyAttributesBasedOnSelectedAlgorithm());
        attributes.addAll(RsaKeyAttributes.getRsaKeySpecAttributes());
        attributes.addAll(EcdsaKeyAttributes.getEcdsaKeySpecAttributes());
        attributes.addAll(FalconKeyAttributes.getFalconKeySpecAttributes());
        attributes.addAll(MLDSAKeyAttributes.getMldsaKeySpecAttributes());
        attributes.addAll(SLHDSAKeyAttributes.getSlhDsaKeySpecAttributes());
        attributes.addAll(MLKEMAttributes.getMLKEMKeySpecAttributes());
        Stream.of(KeyAlgorithm.RSA, KeyAlgorithm.ECDSA).forEach(algorithm -> {
            attributes.addAll(OperationAttributes.signatureAttributes(algorithm));
            attributes.addAll(OperationAttributes.cipherAttributes(algorithm));
        });
        return attributes;
    }
}
