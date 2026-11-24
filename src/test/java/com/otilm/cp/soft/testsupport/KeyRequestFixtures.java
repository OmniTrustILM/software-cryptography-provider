package com.otilm.cp.soft.testsupport;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyExportableAttribute;
import com.otilm.cp.soft.attribute.EcdsaKeyAttributes;
import com.otilm.cp.soft.attribute.KeyAttributes;
import com.otilm.cp.soft.attribute.MLDSAKeyAttributes;
import com.otilm.cp.soft.attribute.MLKEMAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.attribute.SLHDSAKeyAttributes;
import com.otilm.cp.soft.collection.EcdsaCurveName;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

/**
 * Key creation requests as the V2 interfaces carry them, for the tests that need one.
 */
public final class KeyRequestFixtures {

    private KeyRequestFixtures() {
    }

    /** A request creating a 2048-bit RSA key pair under a token of the given name. */
    public static CreateKeyRequestV2Dto rsaKeyPair(String tokenName, String alias) {
        return keyPair(tokenName, rsaAttributes(alias));
    }

    /** A request creating an ML-DSA-65 key pair that signs the message itself, under a token of the given name. */
    public static CreateKeyRequestV2Dto mldsaKeyPair(String tokenName, String alias) {
        return keyPair(tokenName, mldsaAttributes(alias));
    }

    /** A request creating a key pair from the given algorithm and parameter attributes. */
    public static CreateKeyRequestV2Dto keyPair(String tokenName, String alias, List<RequestAttribute> parameters) {
        List<RequestAttribute> attributes = new ArrayList<>(parameters);
        attributes.add(TokenContextFixtures.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS, alias));
        return keyPair(tokenName, attributes);
    }

    /** Key-pair attributes for every algorithm V2 creates, each named after the parameter set it asks for. */
    public static Stream<Arguments> everyKeyPairV2Creates() {
        Stream<Arguments> rsa = Stream
                .of(Arguments
                        .of("RSA-2048", List
                                .of(algorithm(KeyAlgorithm.RSA), stated(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE,
                                        new IntegerAttributeContentV2(2048)))));
        Stream<Arguments> curves = Stream
                .of(EcdsaCurveName.values())
                .map(curve -> Arguments
                        .of("ECDSA " + curve.getName(),
                                List
                                        .of(algorithm(KeyAlgorithm.ECDSA), TokenContextFixtures
                                                .string(EcdsaKeyAttributes.ATTRIBUTE_DATA_ECDSA_CURVE, curve.name()))));
        Stream<Arguments> postQuantum = Stream
                .of(Arguments.of("Falcon-1024", List.of(algorithm(KeyAlgorithm.FALCON))),
                        Arguments
                                .of("ML-DSA-65",
                                        List
                                                .of(algorithm(KeyAlgorithm.MLDSA),
                                                        stated(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_LEVEL,
                                                                new IntegerAttributeContentV2("MLDSA_65", 3)))),
                        Arguments
                                .of("SLH-DSA-SHA2-128F", List
                                        .of(algorithm(KeyAlgorithm.SLHDSA),
                                                stated(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SECURITY_CATEGORY,
                                                        new StringAttributeContentV2("CATEGORY_1", "1")),
                                                stated(SLHDSAKeyAttributes.ATTRIBUTE_DATA_SLHDSA_SIGNATURE_MODE,
                                                        new StringAttributeContentV2("FAST", "FAST")))),
                        Arguments
                                .of("ML-KEM-768",
                                        List
                                                .of(algorithm(KeyAlgorithm.MLKEM),
                                                        stated(MLKEMAttributes.ATTRIBUTE_DATA_MLKEM_LEVEL,
                                                                new IntegerAttributeContentV2("CATEGORY_3", 3)))));
        return Stream.concat(rsa, Stream.concat(curves, postQuantum));
    }

    private static RequestAttribute algorithm(KeyAlgorithm algorithm) {
        return TokenContextFixtures.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, algorithm.getCode());
    }

    private static RequestAttribute stated(String name, BaseAttributeContentV2<?> content) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(content));
        return attribute;
    }

    private static CreateKeyRequestV2Dto keyPair(String tokenName, List<RequestAttribute> keyAttributes) {
        CreateKeyRequestV2Dto request = new CreateKeyRequestV2Dto();
        request.setTokenAttributes(TokenContextFixtures.newToken(tokenName));
        request.setTokenProfileAttributes(List.of());
        request.setKeyRequestType(KeyRequestType.KEY_PAIR);
        request.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        request.setKeyCreationId(UUID.randomUUID().toString());
        request.setCreateKeyAttributes(keyAttributes);
        return request;
    }

    /** The reserved attribute stating whether a created key may ever leave the token. */
    public static RequestAttribute exportableIntent(boolean exportable) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(KeyExportableAttribute.NAME);
        attribute.setContent(List.of(new BooleanAttributeContentV2(exportable)));
        return attribute;
    }

    private static List<RequestAttribute> rsaAttributes(String alias) {
        List<RequestAttribute> attributes = new ArrayList<>();
        attributes.add(TokenContextFixtures.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS, alias));
        attributes.add(TokenContextFixtures.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, "RSA"));

        RequestAttributeV2 keySize = new RequestAttributeV2();
        keySize.setName(RsaKeyAttributes.ATTRIBUTE_DATA_RSA_KEY_SIZE);
        keySize.setContent(List.of(new IntegerAttributeContentV2(2048)));
        attributes.add(keySize);

        return attributes;
    }

    private static List<RequestAttribute> mldsaAttributes(String alias) {
        RequestAttributeV2 level = new RequestAttributeV2();
        level.setName(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_LEVEL);
        level.setContent(List.of(new IntegerAttributeContentV2("MLDSA_65", 3)));

        RequestAttributeV2 prehash = new RequestAttributeV2();
        prehash.setName(MLDSAKeyAttributes.ATTRIBUTE_DATA_MLDSA_PREHASH);
        prehash.setContent(List.of(new BooleanAttributeContentV2(false)));

        return List
                .of(TokenContextFixtures.string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALIAS, alias),
                        TokenContextFixtures
                                .string(KeyAttributes.ATTRIBUTE_DATA_KEY_ALGORITHM, KeyAlgorithm.MLDSA.getCode()),
                        level, prehash);
    }
}
