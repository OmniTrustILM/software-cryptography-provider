package com.otilm.cp.soft.util;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.cp.soft.collection.EcdsaCurveName;
import com.otilm.cp.soft.collection.FalconDegree;
import com.otilm.cp.soft.collection.MLDSASecurityCategory;
import com.otilm.cp.soft.collection.MLKEMSecurityCategory;
import com.otilm.cp.soft.collection.SLHDSAHash;
import com.otilm.cp.soft.collection.SLHDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASignatureMode;
import com.otilm.cp.soft.testsupport.KeyMaterialFixtures;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * An imported key has to be stored the way a generated one is, so that everything reading a token afterwards cannot
 * tell them apart. The size a key row records is the case that can drift: a generated key takes it from the parameter
 * set the request named, and an imported key is measured instead, so the two are compared here for every algorithm.
 */
@SpringBootTest
class ImportedKeyStoreTest {

    private static final String CODE = "00000000";

    /** Each algorithm, with the sizes a generated key of the same parameter set records. */
    private static Stream<Arguments> everyAlgorithm() {
        return Stream
                .of(Arguments
                        .of(KeyAlgorithm.RSA,
                                (Generator) (store, alias) -> KeyStoreUtil.generateRsaKey(store, alias, 2048, CODE),
                                2048, 2048),
                        Arguments
                                .of(KeyAlgorithm.ECDSA,
                                        (Generator) (store, alias) -> KeyStoreUtil
                                                .generateEcdsaKey(store, alias, EcdsaCurveName.secp256r1, CODE),
                                        EcdsaCurveName.secp256r1.getSize() * 2, EcdsaCurveName.secp256r1.getSize()),
                        Arguments
                                .of(KeyAlgorithm.FALCON,
                                        (Generator) (store, alias) -> KeyStoreUtil
                                                .generateFalconKey(store, alias, FalconDegree.FALCON_512, CODE),
                                        FalconDegree.FALCON_512.getPublicKeySize(),
                                        FalconDegree.FALCON_512.getPrivateKeySize()),
                        Arguments
                                .of(KeyAlgorithm.MLDSA, (Generator) (store, alias) -> KeyStoreUtil
                                        .generateMLDSAKey(store, alias, MLDSASecurityCategory.MLDSA_44, false, CODE),
                                        MLDSASecurityCategory.MLDSA_44.getPublicKeySize(),
                                        MLDSASecurityCategory.MLDSA_44.getPrivateKeySize()),
                        Arguments
                                .of(KeyAlgorithm.SLHDSA,
                                        (Generator) (store, alias) -> KeyStoreUtil
                                                .generateSlhDsaKey(store, alias, SLHDSAHash.SHA2,
                                                        SLHDSASecurityCategory.CATEGORY_1, SLHDSASignatureMode.FAST,
                                                        false, CODE),
                                        SLHDSASecurityCategory.CATEGORY_1.getPublicKeySize(),
                                        SLHDSASecurityCategory.CATEGORY_1.getPrivateKeySize()),
                        Arguments
                                .of(KeyAlgorithm.MLKEM,
                                        (Generator) (store, alias) -> KeyStoreUtil
                                                .generateMLKEMKey(store, alias, MLKEMSecurityCategory.CATEGORY_1, CODE),
                                        MLKEMSecurityCategory.CATEGORY_1.getPublicKeySize(),
                                        MLKEMSecurityCategory.CATEGORY_1.getPrivateKeySize()));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("everyAlgorithm")
    void storesAnImportedKeyTheWayAGeneratedOneIsStored(KeyAlgorithm algorithm, Generator generator,
            int generatedPublicSize, int generatedPrivateSize) throws Exception {
        // given a generated key, taken out as protected material the way the platform would send it
        KeyStore keyStore = KeyStoreUtil.loadKeystore(KeyStoreUtil.createNewKeystore("PKCS12", CODE), CODE);
        generator.generate(keyStore, "generated");
        PrivateKey generated = (PrivateKey) keyStore.getKey("generated", CODE.toCharArray());
        KeyPair imported = ImportedKeyMaterial
                .open(KeyMaterialFixtures.protect(generated, KeyMaterialFixtures.PASSPHRASE),
                        KeyMaterialFixtures.PASSPHRASE)
                .keyPair();

        // when it is stored back under another alias, as an import would store it
        ImportedKeyStore.store(keyStore, "imported", algorithm, imported, CODE);

        // then the entry holds the same key, beside a certificate of its own
        assertArrayEquals(generated.getEncoded(),
                ((PrivateKey) keyStore.getKey("imported", CODE.toCharArray())).getEncoded());
        assertNotNull(keyStore.getCertificate("imported"), "a private key entry needs a certificate to be stored");
        assertArrayEquals(imported.getPublic().getEncoded(),
                keyStore.getCertificate("imported").getPublicKey().getEncoded(),
                "the certificate must carry the pair's own public key");

        // and the sizes it records are the ones a generated key of this parameter set records
        assertEquals(generatedPublicSize, ImportedKeyStore.publicKeySize(algorithm, imported));
        assertEquals(generatedPrivateSize, ImportedKeyStore.privateKeySize(algorithm, imported));
    }

    /** How one key of a given algorithm is brought into a keystore, so every algorithm is exercised the same way. */
    @FunctionalInterface
    interface Generator {

        void generate(KeyStore keyStore, String alias);
    }
}
