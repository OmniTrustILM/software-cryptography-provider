package com.otilm.cp.soft.attribute;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.enums.cryptography.EncryptionAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaEncryptionScheme;
import com.otilm.api.model.connector.cryptography.v2.operations.EncryptionAlgorithmAttribute;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.cp.soft.exception.ParameterUnsupportedException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the key-scoped encryption schema and the parameters fixed by each reserved profile.
 */
class OperationAttributesTest {

    private static final List<EncryptionAlgorithm> EXPECTED_RSA_ALGORITHMS = List
            .of(EncryptionAlgorithm.RSA_PKCS1_V1_5, EncryptionAlgorithm.RSA_OAEP_SHA1,
                    EncryptionAlgorithm.RSA_OAEP_SHA256, EncryptionAlgorithm.RSA_OAEP_SHA384,
                    EncryptionAlgorithm.RSA_OAEP_SHA512);

    @Test
    void cipherAttributes_publishesReservedSelectorWithOnlyExplicitlySupportedProfiles() {
        // given
        KeyAlgorithm rsa = KeyAlgorithm.RSA;

        // when
        List<BaseAttribute> attributes = OperationAttributes.cipherAttributes(rsa);

        // then
        assertEquals(List.of(EncryptionAlgorithmAttribute.NAME),
                attributes.stream().map(BaseAttribute::getName).toList());
        DataAttributeV3 selector = (DataAttributeV3) attributes.get(0);
        assertEquals(EncryptionAlgorithmAttribute.ATTRIBUTE_UUID.toString(), selector.getUuid());
        assertTrue(selector.getProperties().isRequired());
        assertEquals(EXPECTED_RSA_ALGORITHMS, profiles(selector));
    }

    @ParameterizedTest
    @EnumSource(value = KeyAlgorithm.class, names = "RSA", mode = EnumSource.Mode.EXCLUDE)
    void cipherAttributesWithoutKeySize_refusesKeysWithoutEncryptionProfiles(KeyAlgorithm algorithm) {
        // given
        // when
        Executable definition = () -> OperationAttributes.cipherAttributes(algorithm);

        // then
        assertThrows(ParameterUnsupportedException.class, definition);
    }

    @ParameterizedTest
    @MethodSource("rsaModulusProfiles")
    void cipherAttributes_offersOnlyProfilesWhosePaddingFits(int modulusBits, List<EncryptionAlgorithm> expected) {
        // given
        KeyAlgorithm rsa = KeyAlgorithm.RSA;

        // when
        DataAttributeV3 selector = (DataAttributeV3) OperationAttributes.cipherAttributes(rsa, modulusBits).get(0);

        // then
        assertEquals(expected, profiles(selector));
    }

    private static Stream<Arguments> rsaModulusProfiles() {
        return Stream
                .of(Arguments.of(512, List.of(EncryptionAlgorithm.RSA_PKCS1_V1_5, EncryptionAlgorithm.RSA_OAEP_SHA1)),
                        Arguments
                                .of(1024, List
                                        .of(EncryptionAlgorithm.RSA_PKCS1_V1_5, EncryptionAlgorithm.RSA_OAEP_SHA1,
                                                EncryptionAlgorithm.RSA_OAEP_SHA256,
                                                EncryptionAlgorithm.RSA_OAEP_SHA384)),
                        Arguments.of(2048, EXPECTED_RSA_ALGORITHMS));
    }

    @ParameterizedTest
    @EnumSource(value = KeyAlgorithm.class, names = "RSA", mode = EnumSource.Mode.EXCLUDE)
    void cipherAttributes_refusesKeysWithoutEncryptionProfiles(KeyAlgorithm algorithm) {
        // given
        int keyLength = 2048;

        // when
        Executable definition = () -> OperationAttributes.cipherAttributes(algorithm, keyLength);

        // then
        assertThrows(ParameterUnsupportedException.class, definition);
    }

    @ParameterizedTest
    @EnumSource(value = KeyAlgorithm.class, names = "RSA", mode = EnumSource.Mode.EXCLUDE)
    void cipherParameters_refusesUnsupportedKeyBeforeValidatingMissingSelection(KeyAlgorithm algorithm) {
        // given
        int keyLength = 2048;
        List<RequestAttribute> missingSelection = List.of();

        // when
        Executable conversion = () -> OperationAttributes.cipherParameters(algorithm, keyLength, missingSelection);

        // then
        assertThrows(ParameterUnsupportedException.class, conversion);
    }

    @ParameterizedTest
    @EnumSource(value = KeyAlgorithm.class, names = "RSA", mode = EnumSource.Mode.EXCLUDE)
    void cipherParameters_refusesUnsupportedKeyBeforeValidatingLegacyAttributes(KeyAlgorithm algorithm) {
        // given
        int keyLength = 2048;
        List<RequestAttribute> legacy = List
                .of(string(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME,
                        RsaEncryptionScheme.PKCS1_v1_5.getCode()));

        // when
        Executable conversion = () -> OperationAttributes.cipherParameters(algorithm, keyLength, legacy);

        // then
        assertThrows(ParameterUnsupportedException.class, conversion);
    }

    @Test
    void cipherParameters_requiresReservedSelectionForSupportedKey() {
        // given
        KeyAlgorithm algorithm = KeyAlgorithm.RSA;
        int modulusBits = 2048;
        List<RequestAttribute> missingSelection = List.of();

        // when
        Executable conversion = () -> OperationAttributes.cipherParameters(algorithm, modulusBits, missingSelection);

        // then
        assertThrows(ValidationException.class, conversion);
    }

    @Test
    void cipherParameters_mapsPkcs1SelectionToSharedCipherScheme() {
        // given
        EncryptionAlgorithm selected = EncryptionAlgorithm.RSA_PKCS1_V1_5;

        // when
        List<RequestAttribute> parameters = parameters(selected);

        // then
        assertEquals(1, parameters.size());
        assertEquals(RsaEncryptionScheme.PKCS1_v1_5.getCode(), scheme(parameters));
    }

    @ParameterizedTest
    @MethodSource("oaepProfiles")
    void cipherParameters_fixesOaepHashAndMatchingMgf1(EncryptionAlgorithm selected, String expectedHash) {
        // given
        // when
        List<RequestAttribute> parameters = parameters(selected);

        // then
        assertEquals(3, parameters.size());
        assertEquals(RsaEncryptionScheme.OAEP.getCode(), scheme(parameters));
        assertEquals(expectedHash,
                AttributeDefinitionUtils
                        .getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME,
                                parameters, StringAttributeContentV2.class)
                        .getData());
        assertTrue(AttributeDefinitionUtils
                .getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME,
                        parameters, BooleanAttributeContentV2.class)
                .getData());
    }

    private static Stream<Arguments> oaepProfiles() {
        return Stream
                .of(Arguments.of(EncryptionAlgorithm.RSA_OAEP_SHA1, "SHA-1"),
                        Arguments.of(EncryptionAlgorithm.RSA_OAEP_SHA256, "SHA-256"),
                        Arguments.of(EncryptionAlgorithm.RSA_OAEP_SHA384, "SHA-384"),
                        Arguments.of(EncryptionAlgorithm.RSA_OAEP_SHA512, "SHA-512"));
    }

    @Test
    void cipherParameters_refusesSelectionWhosePaddingDoesNotFit() {
        // given
        int modulusBits = 1024;
        List<RequestAttribute> selection = List
                .of(EncryptionAlgorithmAttribute.request(EncryptionAlgorithm.RSA_OAEP_SHA512));

        // when
        Executable conversion = () -> OperationAttributes.cipherParameters(KeyAlgorithm.RSA, modulusBits, selection);

        // then
        assertThrows(ParameterUnsupportedException.class, conversion);
    }

    @Test
    void cipherParameters_requiresReservedSelectionInsteadOfLegacyScheme() {
        // given
        List<RequestAttribute> legacy = List
                .of(string(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME,
                        RsaEncryptionScheme.PKCS1_v1_5.getCode()));

        // when
        Executable conversion = () -> OperationAttributes.cipherParameters(KeyAlgorithm.RSA, 2048, legacy);

        // then
        assertThrows(ValidationException.class, conversion);
    }

    @Test
    void cipherParameters_preventsLegacyAttributesFromOverridingReservedProfile() {
        // given
        List<RequestAttribute> selection = new ArrayList<>(
                List.of(EncryptionAlgorithmAttribute.request(EncryptionAlgorithm.RSA_OAEP_SHA256)));
        selection
                .add(string(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME,
                        RsaEncryptionScheme.PKCS1_v1_5.getCode()));
        selection.add(string(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME, "SHA-1"));

        // when
        List<RequestAttribute> parameters = OperationAttributes.cipherParameters(KeyAlgorithm.RSA, 2048, selection);

        // then
        assertEquals(RsaEncryptionScheme.OAEP.getCode(), scheme(parameters));
        assertEquals("SHA-256",
                AttributeDefinitionUtils
                        .getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME,
                                parameters, StringAttributeContentV2.class)
                        .getData());
    }

    private static List<EncryptionAlgorithm> profiles(DataAttributeV3 selector) {
        return selector
                .getContent()
                .stream()
                .map(content -> EncryptionAlgorithm.findByCode((String) content.getData()))
                .toList();
    }

    private static List<RequestAttribute> parameters(EncryptionAlgorithm selected) {
        return OperationAttributes
                .cipherParameters(KeyAlgorithm.RSA, 2048, List.of(EncryptionAlgorithmAttribute.request(selected)));
    }

    private static String scheme(List<RequestAttribute> parameters) {
        return AttributeDefinitionUtils
                .getSingleItemAttributeContentValue(RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME, parameters,
                        StringAttributeContentV2.class)
                .getData();
    }

    private static RequestAttribute string(String name, String value) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(new StringAttributeContentV2(value, value)));
        return attribute;
    }
}
