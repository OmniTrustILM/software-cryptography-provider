package com.otilm.cp.soft.collection;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The sizes a key row records are in bits, and every ML-KEM key is a whole number of bytes, so a size that is not
 * divisible by eight is a mistyped one rather than a parameter set.
 */
class MLKEMSecurityCategoryTest {

    private static final int BITS_PER_BYTE = 8;

    @ParameterizedTest
    @EnumSource(MLKEMSecurityCategory.class)
    void statesSizesThatAreWholeBytes(MLKEMSecurityCategory category) {
        // given
        // when
        // then
        assertEquals(0, category.getPublicKeySize() % BITS_PER_BYTE, () -> category.getParameterSet()
                + " states an encapsulation key of " + category.getPublicKeySize() + " bits");
        assertEquals(0, category.getPrivateKeySize() % BITS_PER_BYTE, () -> category.getParameterSet()
                + " states a decapsulation key of " + category.getPrivateKeySize() + " bits");
    }
}
