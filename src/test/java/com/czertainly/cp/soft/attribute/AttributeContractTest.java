package com.czertainly.cp.soft.attribute;

import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The identifiers the platform stores against token and key configuration.
 *
 * <p>Every expected value here is a literal on purpose. The other attribute tests refer to
 * the constants for readability, which makes them useful for structure but blind to identity:
 * renaming a constant or editing a UUID changes the builder and the expectation together, so
 * such a test stays green while every existing configuration is orphaned. These literals are
 * the copy that does not move, so a change to any published identifier fails here.</p>
 */
class AttributeContractTest {

    private static Stream<Arguments> publishedAttributes() {
        return Stream.of(
                Arguments.of(TokenInstanceAttributes.buildDataCreateTokenAction("new"),
                        "cc781ba3-d90b-4fe9-915a-e8d44e1cff86", "data_createTokenAction"),
                Arguments.of(TokenInstanceAttributes.buildInfoNewToken(),
                        "15943f63-8b06-45f6-bad6-58e0998b654b", "info_newToken"),
                Arguments.of(TokenInstanceAttributes.buildDataNewTokenName(),
                        "21a79858-a246-4b2a-93e1-1677c8beb6a4", "data_newTokenName"),
                Arguments.of(TokenInstanceAttributes.buildDataTokenCode(),
                        "181aae19-d2a3-40ca-b5c7-570c8dfbb3cb", "data_tokenCode"),
                Arguments.of(TokenInstanceAttributes.buildInitialInfo(),
                        "320c401a-9feb-402a-8f5b-0bfefcf155cc", "info_initial"),
                Arguments.of(TokenInstanceAttributes.buildOptions(),
                        "6285683f-f474-4b21-a0ff-56accf28c604", "data_options"),
                Arguments.of(TokenInstanceAttributes.buildDataSelectExistingToken(List.of()),
                        "a12bb85a-93a9-4c05-9d7d-5b253298bbaf", "data_existingToken"),
                Arguments.of(TokenInstanceAttributes.buildGroupBasedOnSelect(),
                        "5dfc0040-a530-4faa-bc07-5fed6779b474", "group_loadToken"),
                Arguments.of(TokenInstanceActivationAttributes.buildDataTokenActivationCode(),
                        "0d4044f0-2af0-4f10-ac09-319072eb3393", "data_tokenActivationCode"),
                Arguments.of(KeyAttributes.buildDataKeyAlias(),
                        "61a228de-c54e-461e-b0d7-ad156a547b51", "data_keyAlias"),
                Arguments.of(KeyAttributes.buildDataKeyAlgorithmSelect(),
                        "72159c04-d1a9-4703-8b23-469224425d5f", "data_keyAlgorithm"),
                Arguments.of(KeyAttributes.buildGroupKeyAttributesBasedOnSelectedAlgorithm(),
                        "dfcfb71f-a161-4aa7-8b1f-726b477b3492", "group_keySpec"),
                Arguments.of(KeyAttributes.buildAliasMetadata("alias"),
                        "a5575bb8-dd88-4b60-bb73-75b862da78aa", "meta_keyAlias"),
                Arguments.of(RsaKeyAttributes.buildDataRsaKeySize(),
                        "aa7df6ff-1d64-4a1a-96d6-6c7aeadfbdf3", "data_rsaKeySize"),
                Arguments.of(RsaKeyAttributes.buildRsaKeySizeMetadata(2048),
                        "6b8c8b9d-2712-4f9e-ab60-007cf19ac1d4", "meta_rsaKeySize"),
                Arguments.of(EcdsaKeyAttributes.buildDataEscdaNamedCurves(),
                        "08730b36-90f3-4046-9f13-3cf827ad6cc7", "data_ecdsaCurve"),
                Arguments.of(FalconKeyAttributes.buildDataFalconDegree(),
                        "d4d86b9a-b5df-4a1b-8d9d-1671cfb4b496", "data_falconDegree"),
                Arguments.of(FalconKeyAttributes.buildFalconDegreeMetadata(512),
                        "bd9b2826-f7fc-4bc3-b817-66bc231f1ee2", "meta_falconDegree"),
                Arguments.of(MLDSAKeyAttributes.buildDataMLDSASecurityCategory(),
                        "22e317d6-dd78-4968-9a26-c1823a4fb2e6", "data_mldsaLevel"),
                Arguments.of(MLDSAKeyAttributes.buildBooleanPreHash(),
                        "dd1a8f25-a529-42a6-9c3d-3b9a70fc7e9b", "data_mldsaPrehash"),
                Arguments.of(MLKEMAttributes.buildDataMLKEMSecurityCategory(),
                        "b574e0fb-9db5-4864-9652-40ccf9cff64d", "data_mlkemLevel"),
                Arguments.of(SLHDSAKeyAttributes.buildDataSecurityCategory(),
                        "b4d4cf43-d214-42e5-a402-3db66d9c1c6c", "data_slhdsaSecurityCategory"),
                Arguments.of(SLHDSAKeyAttributes.buildDataHash(),
                        "fd0dddbf-3cb5-477d-a3e2-6ebe8c1ec639", "data_slhdsaHash"),
                Arguments.of(SLHDSAKeyAttributes.buildDataSignatureMode(),
                        "7a33f35a-8e32-4bcc-bf3e-37654b6a8107", "data_slhdsaSignatureMode"),
                Arguments.of(SLHDSAKeyAttributes.buildBooleanPreHash(),
                        "81f20bdd-ec84-4a7f-9c9d-13efce16665a", "data_slhdsaPrehash")
        );
    }

    @ParameterizedTest(name = "{2}")
    @MethodSource("publishedAttributes")
    void publishedIdentifiersMustNotChange(BaseAttribute attribute, String uuid, String name) {
        assertEquals(uuid, attribute.getUuid(),
                name + " changed UUID; every stored configuration referencing it would be orphaned");
        assertEquals(name, attribute.getName(),
                uuid + " changed name; every stored configuration referencing it would be orphaned");
        assertDoesNotThrow(() -> UUID.fromString(attribute.getUuid()), name + " has a malformed UUID");
    }

    @Test
    void cipherAttributeNamesMustNotChange() {
        // Sent by the platform on cipher operations; the connector reads them by name only.
        assertEquals("data_rsaEncScheme", RsaCipherAttributes.ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME);
        assertEquals("data_rsaOaepHash", RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME);
        assertEquals("data_rsaOaepMgf", RsaCipherAttributes.ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME);
    }

    @Test
    void attributeCallbackPathsMustNotChange() {
        assertEquals("/v1/cryptographyProvider/callbacks/token/{option}/attributes",
                ((com.czertainly.api.model.common.attribute.v2.GroupAttributeV2)
                        TokenInstanceAttributes.buildGroupBasedOnSelect())
                        .getAttributeCallback().getCallbackContext());
        assertEquals("/v1/cryptographyProvider/callbacks/keyspec/{algorithm}/attributes",
                ((com.czertainly.api.model.common.attribute.v2.GroupAttributeV2)
                        KeyAttributes.buildGroupKeyAttributesBasedOnSelectedAlgorithm())
                        .getAttributeCallback().getCallbackContext());
    }

}
