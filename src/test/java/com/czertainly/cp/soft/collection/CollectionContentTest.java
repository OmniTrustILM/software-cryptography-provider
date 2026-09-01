package com.czertainly.cp.soft.collection;

import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The attribute content offered for each key specification option. The reference of every
 * entry is what a stored key configuration is resolved against, so these lists are part of
 * the connector's contract.
 *
 * <p>The expected references are literals rather than {@code values()}. Deriving them from
 * the enum under test would move both sides of the comparison together, leaving a rename
 * green while it orphaned every key configured against the old reference.</p>
 */
class CollectionContentTest {

    private static Stream<Arguments> contentLists() {
        return Stream.of(
                Arguments.of("RsaKeySize", RsaKeySize.asIntegerAttributeContentList(),
                        List.of("RSA_1024", "RSA_2048", "RSA_4096")),
                Arguments.of("FalconDegree", FalconDegree.asIntegerAttributeContentList(),
                        List.of("FALCON_512", "FALCON_1024")),
                Arguments.of("MLDSASecurityCategory", MLDSASecurityCategory.asIntegerAttributeContentList(),
                        List.of("MLDSA_44", "MLDSA_65", "MLDSA_87")),
                Arguments.of("MLKEMSecurityCategory", MLKEMSecurityCategory.asIntegerAttributeContentList(),
                        List.of("CATEGORY_1", "CATEGORY_3", "CATEGORY_5")),
                Arguments.of("EcdsaCurveName", EcdsaCurveName.asStringAttributeContentList(),
                        List.of("secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1")),
                Arguments.of("SLHDSAHash", SLHDSAHash.asStringAttributeContentList(),
                        List.of("SHA2", "SHAKE256")),
                Arguments.of("SLHDSASecurityCategory", SLHDSASecurityCategory.asStringAttributeContentList(),
                        List.of("CATEGORY_1", "CATEGORY_3", "CATEGORY_5")),
                Arguments.of("SLHDSASignatureMode", SLHDSASignatureMode.asStringAttributeContentList(),
                        List.of("FAST", "SMALL"))
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("contentLists")
    void contentListOffersEveryConstantByName(String label, List<BaseAttributeContentV2<?>> content,
                                              List<String> expectedReferences) {
        assertFalse(content.isEmpty(), label + " offers no content");
        assertEquals(expectedReferences, content.stream().map(BaseAttributeContentV2::getReference).toList(),
                label + " must offer every constant, referenced by name");
        assertTrue(content.stream().allMatch(c -> c.getData() != null), label + " has an entry without data");
    }

    @Test
    void integerContentCarriesTheNumericValue() {
        assertEquals(List.of(1024, 2048, 4096), dataOf(RsaKeySize.asIntegerAttributeContentList()));
        assertEquals(List.of(512, 1024), dataOf(FalconDegree.asIntegerAttributeContentList()));
        assertEquals(List.of(2, 3, 5), dataOf(MLDSASecurityCategory.asIntegerAttributeContentList()));
        assertEquals(List.of(1, 3, 5), dataOf(MLKEMSecurityCategory.asIntegerAttributeContentList()));
    }

    @Test
    void stringContentCarriesTheWireName() {
        assertEquals(List.of("secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1"),
                dataOf(EcdsaCurveName.asStringAttributeContentList()));
        assertEquals(List.of("SHA2", "SHAKE"), dataOf(SLHDSAHash.asStringAttributeContentList()));
        assertEquals(List.of("1", "3", "5"), dataOf(SLHDSASecurityCategory.asStringAttributeContentList()));
    }

    @Test
    void signatureModeUsesTheConstantNameAsBothReferenceAndData() {
        // Built with the single-argument constructor, which sets reference and data alike.
        List<BaseAttributeContentV2<?>> content = SLHDSASignatureMode.asStringAttributeContentList();
        assertEquals(List.of("FAST", "SMALL"), dataOf(content));
    }

    @Test
    void signatureModeParameterNamesMatchTheStandard() {
        assertEquals("f", SLHDSASignatureMode.FAST.getParameterName());
        assertEquals("s", SLHDSASignatureMode.SMALL.getParameterName());
    }

    @Test
    void hashNamesMapToTheBouncyCastleSpelling() {
        assertEquals("SHA2", SLHDSAHash.SHA2.getHashName());
        assertEquals("SHAKE", SLHDSAHash.SHAKE256.getHashName());
        assertEquals("SHAKE256", SLHDSAHash.SHAKE256.toString());
    }

    private static List<Object> dataOf(List<BaseAttributeContentV2<?>> content) {
        assertNotNull(content);
        return content.stream().map(c -> (Object) c.getData()).toList();
    }
}
