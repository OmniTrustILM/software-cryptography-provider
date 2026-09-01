package com.otilm.cp.soft.collection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Key material sizes and parameter set names for the post-quantum algorithms. These are fixed by the relevant standards
 * and are used to size buffers and to label generated keys, so they are pinned here rather than left to be changed by
 * accident.
 */
class CollectionKeySizeTest {

    @Test
    void falconKeySizes() {
        assertEquals(512, FalconDegree.FALCON_512.getDegree());
        assertEquals(7176, FalconDegree.FALCON_512.getPublicKeySize());
        assertEquals(10088, FalconDegree.FALCON_512.getPrivateKeySize());

        assertEquals(1024, FalconDegree.FALCON_1024.getDegree());
        assertEquals(14344, FalconDegree.FALCON_1024.getPublicKeySize());
        assertEquals(18440, FalconDegree.FALCON_1024.getPrivateKeySize());
    }

    @Test
    void mldsaCategoriesFollowFips204() {
        assertEquals(2, MLDSASecurityCategory.MLDSA_44.getNistSecurityCategory());
        assertEquals("44", MLDSASecurityCategory.MLDSA_44.getParameterSet());
        assertEquals(10496, MLDSASecurityCategory.MLDSA_44.getPublicKeySize());
        assertEquals(20480, MLDSASecurityCategory.MLDSA_44.getPrivateKeySize());

        assertEquals("65", MLDSASecurityCategory.MLDSA_65.getParameterSet());
        assertEquals("87", MLDSASecurityCategory.MLDSA_87.getParameterSet());
        assertEquals(5, MLDSASecurityCategory.MLDSA_87.getNistSecurityCategory());
    }

    @Test
    void mlkemCategoriesFollowFips203() {
        assertEquals(1, MLKEMSecurityCategory.CATEGORY_1.getNistSecurityCategory());
        assertEquals("ML-KEM-512", MLKEMSecurityCategory.CATEGORY_1.getParameterSet());
        assertEquals(6400, MLKEMSecurityCategory.CATEGORY_1.getPublicKeySize());

        assertEquals("ML-KEM-768", MLKEMSecurityCategory.CATEGORY_3.getParameterSet());
        assertEquals("ML-KEM-1024", MLKEMSecurityCategory.CATEGORY_5.getParameterSet());
        assertEquals(5, MLKEMSecurityCategory.CATEGORY_5.getNistSecurityCategory());
    }

    @Test
    void slhdsaCategoriesFollowFips205() {
        assertEquals("1", SLHDSASecurityCategory.CATEGORY_1.getNistSecurityCategory());
        assertEquals("128", SLHDSASecurityCategory.CATEGORY_1.getSecurityParameterLength());
        assertEquals(256, SLHDSASecurityCategory.CATEGORY_1.getPublicKeySize());
        assertEquals(512, SLHDSASecurityCategory.CATEGORY_1.getPrivateKeySize());

        assertEquals("192", SLHDSASecurityCategory.CATEGORY_3.getSecurityParameterLength());
        assertEquals("256", SLHDSASecurityCategory.CATEGORY_5.getSecurityParameterLength());
        assertEquals(1024, SLHDSASecurityCategory.CATEGORY_5.getPrivateKeySize());
    }

    @Test
    void ecdsaCurvesCarryTheirFieldSizeAndDescription() {
        assertEquals(192, EcdsaCurveName.secp192r1.getSize());
        assertEquals("secp192r1", EcdsaCurveName.secp192r1.getName());
        assertEquals("NIST/SECG curve over a 192 bit prime field", EcdsaCurveName.secp192r1.getDescription());

        assertEquals(256, EcdsaCurveName.secp256r1.getSize());
        assertEquals(512, EcdsaCurveName.secp521r1.getSize());
    }

    @Test
    void rsaKeySizesAreTheSupportedSet() {
        assertEquals(1024, RsaKeySize.RSA_1024.getSize());
        assertEquals(2048, RsaKeySize.RSA_2048.getSize());
        assertEquals(4096, RsaKeySize.RSA_4096.getSize());
    }
}
