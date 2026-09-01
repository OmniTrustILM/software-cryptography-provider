package com.czertainly.cp.soft.collection;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.function.IntFunction;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Numeric lookup shared by the key specification collections. Stored key configuration is
 * resolved through these, so an unknown value must be rejected rather than silently mapped.
 */
class CollectionLookupTest {

    private static Stream<Arguments> lookups() {
        return Stream.of(
                Arguments.of("RsaKeySize", (IntFunction<Object>) RsaKeySize::valueOf,
                        (IntFunction<Object>) RsaKeySize::resolve, 2048, RsaKeySize.RSA_2048, 1234),
                Arguments.of("FalconDegree", (IntFunction<Object>) FalconDegree::valueOf,
                        (IntFunction<Object>) FalconDegree::resolve, 512, FalconDegree.FALCON_512, 768),
                Arguments.of("MLDSASecurityCategory", (IntFunction<Object>) MLDSASecurityCategory::valueOf,
                        (IntFunction<Object>) MLDSASecurityCategory::resolve, 3, MLDSASecurityCategory.MLDSA_65, 4),
                Arguments.of("MLKEMSecurityCategory", (IntFunction<Object>) MLKEMSecurityCategory::valueOf,
                        (IntFunction<Object>) MLKEMSecurityCategory::resolve, 5, MLKEMSecurityCategory.CATEGORY_5, 2)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("lookups")
    void knownValueResolvesToItsConstant(String label, IntFunction<Object> valueOf, IntFunction<Object> resolve,
                                         int known, Object expected, int unknown) {
        assertSame(expected, valueOf.apply(known), label + " did not resolve a known value");
        assertSame(expected, resolve.apply(known), label + " resolve disagreed with valueOf");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("lookups")
    void unknownValueIsRejected(String label, IntFunction<Object> valueOf, IntFunction<Object> resolve,
                                int known, Object expected, int unknown) {
        assertNull(resolve.apply(unknown), label + " resolve must return null for an unknown value");
        IllegalArgumentException thrown =
                assertThrows(IllegalArgumentException.class, () -> valueOf.apply(unknown),
                        label + " valueOf must reject an unknown value");
        assertEquals("No matching constant for [" + unknown + "]", thrown.getMessage());
    }

    @Test
    void enumValueOfByNameStillWorksAlongsideTheNumericOverload() {
        assertSame(RsaKeySize.RSA_4096, RsaKeySize.valueOf("RSA_4096"));
        assertSame(FalconDegree.FALCON_1024, FalconDegree.valueOf("FALCON_1024"));
        assertSame(MLDSASecurityCategory.MLDSA_87, MLDSASecurityCategory.valueOf("MLDSA_87"));
        assertSame(MLKEMSecurityCategory.CATEGORY_1, MLKEMSecurityCategory.valueOf("CATEGORY_1"));
    }

    @Test
    void toStringIsTheFormUsedInLogsAndLabels() {
        assertEquals("2048 RSA_2048", RsaKeySize.RSA_2048.toString());
        assertEquals("512 FALCON_512", FalconDegree.FALCON_512.toString());
        assertEquals("secp256r1 secp256r1", EcdsaCurveName.secp256r1.toString());
        assertEquals("MLDSA_44", MLDSASecurityCategory.MLDSA_44.toString());
        assertEquals("CATEGORY_3", MLKEMSecurityCategory.CATEGORY_3.toString());
        assertEquals("3", SLHDSASecurityCategory.CATEGORY_3.toString());
    }
}
