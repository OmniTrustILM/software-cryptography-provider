package com.otilm.cp.soft.util;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The SPHINCS+ provider is still registered alongside SLH-DSA, so keys generated under the
 * pre-standard name must keep working for tokens created before the rename.
 */
class SphincsPlusTest {

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    @Test
    void sphincsPlusKeyPairIsGeneratedForTheRequestedParameterSet()
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("SPHINCSPlus", BouncyCastlePQCProvider.PROVIDER_NAME);
        generator.initialize(SPHINCSPlusParameterSpec.sha2_128f);

        KeyPair keyPair = generator.generateKeyPair();

        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        // The parameter set is part of the reported algorithm name.
        assertEquals("SPHINCS+-SHA2-128F", keyPair.getPublic().getAlgorithm());
        assertTrue(keyPair.getPublic().getEncoded().length > 0);
    }

    @Test
    void sphincsPlusKeyPairSignsAndVerifies() throws Exception {
        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("SPHINCSPlus", BouncyCastlePQCProvider.PROVIDER_NAME);
        generator.initialize(SPHINCSPlusParameterSpec.sha2_128f);
        KeyPair keyPair = generator.generateKeyPair();

        byte[] data = "data to be signed".getBytes();

        Signature signer = Signature.getInstance("SPHINCSPlus", BouncyCastlePQCProvider.PROVIDER_NAME);
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SPHINCSPlus", BouncyCastlePQCProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(data);
        assertTrue(verifier.verify(signature));
    }
}
