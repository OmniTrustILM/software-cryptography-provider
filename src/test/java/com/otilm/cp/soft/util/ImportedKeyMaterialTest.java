package com.otilm.cp.soft.util;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.material.EncryptedKeyMaterialV2Dto;
import com.otilm.cp.soft.collection.EcdsaCurveName;
import com.otilm.cp.soft.collection.FalconDegree;
import com.otilm.cp.soft.collection.MLDSASecurityCategory;
import com.otilm.cp.soft.collection.MLKEMSecurityCategory;
import com.otilm.cp.soft.collection.SLHDSAHash;
import com.otilm.cp.soft.collection.SLHDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASignatureMode;
import com.otilm.cp.soft.exception.KeyManagementException;
import com.otilm.cp.soft.testsupport.KeyMaterialFixtures;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Key material arrives carrying only the private key and nothing that names its algorithm, so both have to be read out
 * of the material itself. The provider stores both halves of a pair, so an import that cannot produce the public half
 * cannot be stored at all.
 *
 * <p>
 * Loaded as an application test because the security providers the reading depends on are registered by the
 * application.
 * </p>
 */
@SpringBootTest
class ImportedKeyMaterialTest {

    private static final String CODE = "00000000";

    /** One key of each algorithm the provider can create, since import advertises exactly that set. */
    private static Stream<Arguments> everyAlgorithmTheProviderSupports() {
        return Stream
                .of(Arguments
                        .of(KeyAlgorithm.RSA,
                                (Generator) (store, alias) -> KeyStoreUtil.generateRsaKey(store, alias, 2048, CODE)),
                        Arguments
                                .of(KeyAlgorithm.ECDSA,
                                        (Generator) (store, alias) -> KeyStoreUtil
                                                .generateEcdsaKey(store, alias, EcdsaCurveName.secp256r1, CODE)),
                        Arguments
                                .of(KeyAlgorithm.FALCON,
                                        (Generator) (store, alias) -> KeyStoreUtil
                                                .generateFalconKey(store, alias, FalconDegree.FALCON_512, CODE)),
                        Arguments
                                .of(KeyAlgorithm.MLDSA, (Generator) (store, alias) -> KeyStoreUtil
                                        .generateMLDSAKey(store, alias, MLDSASecurityCategory.MLDSA_44, false, CODE)),
                        Arguments
                                .of(KeyAlgorithm.SLHDSA,
                                        (Generator) (store, alias) -> KeyStoreUtil
                                                .generateSlhDsaKey(store, alias, SLHDSAHash.SHA2,
                                                        SLHDSASecurityCategory.CATEGORY_1, SLHDSASignatureMode.FAST,
                                                        false, CODE)),
                        Arguments
                                .of(KeyAlgorithm.MLKEM, (Generator) (store, alias) -> KeyStoreUtil
                                        .generateMLKEMKey(store, alias, MLKEMSecurityCategory.CATEGORY_1, CODE)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("everyAlgorithmTheProviderSupports")
    void readsTheAlgorithmAndBothHalvesOutOfTheMaterial(KeyAlgorithm expected, Generator generator) throws Exception {
        // given
        KeyStore keyStore = KeyStoreUtil.loadKeystore(KeyStoreUtil.createNewKeystore("PKCS12", CODE), CODE);
        generator.generate(keyStore, "source");
        PrivateKey original = (PrivateKey) keyStore.getKey("source", CODE.toCharArray());
        PublicKey originalPublic = keyStore.getCertificate("source").getPublicKey();
        byte[] material = KeyMaterialFixtures.protect(original, KeyMaterialFixtures.PASSPHRASE);

        // when
        ImportedKeyMaterial opened = ImportedKeyMaterial.open(material, KeyMaterialFixtures.PASSPHRASE);

        // then
        assertEquals(expected, opened.algorithm());
        assertArrayEquals(original.getEncoded(), opened.keyPair().getPrivate().getEncoded(),
                "the private key that went in is the one that comes out");
        assertNotNull(opened.keyPair().getPublic(), "the public half has to be worked out to store the pair");
        assertArrayEquals(originalPublic.getEncoded(), opened.keyPair().getPublic().getEncoded(),
                "the public half worked out from the private key must be the pair's own");
    }

    /**
     * The contract states one protection profile and refuses an envelope outside it before the connector opens
     * anything, so what is protected here has to satisfy the contract's own reading of the envelope.
     */
    @Test
    void protectsMaterialTheContractAccepts() throws Exception {
        // given
        KeyStore keyStore = KeyStoreUtil.loadKeystore(KeyStoreUtil.createNewKeystore("PKCS12", CODE), CODE);
        KeyStoreUtil.generateRsaKey(keyStore, "source", 2048, CODE);
        PrivateKey original = (PrivateKey) keyStore.getKey("source", CODE.toCharArray());

        // when
        EncryptedKeyMaterialV2Dto material = new EncryptedKeyMaterialV2Dto();
        material.setEncryptedPrivateKeyInfo(KeyMaterialFixtures.protect(original, KeyMaterialFixtures.PASSPHRASE));

        // then
        assertTrue(material.isWithinMaximumLength(), "the envelope must be short enough to parse");
        assertTrue(material.isCanonicalEnvelope(), "the envelope must be canonical DER");
        assertTrue(material.isPinnedProtectionScheme(),
                "the scheme must be PBES2 over PBKDF2-HMAC-SHA256 with AES-256-CBC");
        assertTrue(material.isPinnedProtectionParameters(),
                "the salt, iterations and initialisation vector must sit in range");
        assertTrue(material.isWholeCipherBlocks(), "the ciphertext must be whole AES blocks");
    }

    /** The profile carries no integrity protection, so a wrong passphrase shows up as material that will not open. */
    @Test
    void refusesMaterialThePassphraseDoesNotOpen() throws Exception {
        // given
        KeyStore keyStore = KeyStoreUtil.loadKeystore(KeyStoreUtil.createNewKeystore("PKCS12", CODE), CODE);
        KeyStoreUtil.generateRsaKey(keyStore, "source", 2048, CODE);
        PrivateKey original = (PrivateKey) keyStore.getKey("source", CODE.toCharArray());
        byte[] material = KeyMaterialFixtures.protect(original, KeyMaterialFixtures.PASSPHRASE);

        // when
        // then
        assertThrows(KeyManagementException.class, () -> ImportedKeyMaterial.open(material, "another passphrase"));
    }

    @Test
    void refusesBytesThatAreNotProtectedKeyMaterial() {
        // given
        byte[] notMaterial = "this is not an envelope".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // when
        // then
        assertThrows(KeyManagementException.class,
                () -> ImportedKeyMaterial.open(notMaterial, KeyMaterialFixtures.PASSPHRASE));
    }

    /** How one key of a given algorithm is brought into a keystore, so every algorithm is exercised the same way. */
    @FunctionalInterface
    interface Generator {

        void generate(KeyStore keyStore, String alias);
    }
}
