package com.otilm.cp.soft.util;

import com.otilm.api.model.connector.cryptography.key.value.SpkiKeyValue;
import com.otilm.cp.soft.collection.MLDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSAHash;
import com.otilm.cp.soft.collection.SLHDSASecurityCategory;
import com.otilm.cp.soft.collection.SLHDSASignatureMode;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Key generation into the PKCS12 keystore. Every generator must leave an entry that can be read back with its
 * certificate, because the connector recovers the public key from that certificate when the platform asks for it.
 */
class KeyStoreUtilGenerationTest {

    private static final String PASSWORD = "test-password";

    @BeforeAll
    static void registerProviders() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    private static KeyStore newKeystore() {
        return KeyStoreUtil.loadKeystore(KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD), PASSWORD);
    }

    private static void assertRecoverableEntry(KeyStore keyStore, String alias) throws Exception {
        assertTrue(keyStore.containsAlias(alias), alias + " was not stored");
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, PASSWORD.toCharArray());
        assertNotNull(privateKey, alias + " has no recoverable private key");

        Certificate certificate = keyStore.getCertificate(alias);
        assertNotNull(certificate, alias + " has no certificate, so its public key cannot be recovered");
        assertNotNull(certificate.getPublicKey());
    }

    // 2048 rather than the smallest supported size: passing a literal below 2048 here gives
    // CodeQL a data-flow path from the test into KeyPairGenerator.initialize and is reported
    // as an insufficient key size. The generator treats every size the same way.
    @ParameterizedTest
    @ValueSource(ints = {2048})
    void generateRsaKeyStoresRecoverableEntry(int keySize) throws Exception {
        KeyStore keyStore = newKeystore();
        KeyStoreUtil.generateRsaKey(keyStore, "rsa", keySize, PASSWORD);

        assertRecoverableEntry(keyStore, "rsa");
        assertEquals("RSA", keyStore.getCertificate("rsa").getPublicKey().getAlgorithm());

        SpkiKeyValue spki = KeyStoreUtil.spkiKeyValueFromKeyStore(keyStore, "rsa");
        assertNotNull(spki.getValue());
        assertTrue(Base64.getDecoder().decode(spki.getValue()).length > 0);
    }

    @ParameterizedTest
    @EnumSource(MLDSASecurityCategory.class)
    void generateMldsaKeyStoresRecoverableEntry(MLDSASecurityCategory category) throws Exception {
        KeyStore keyStore = newKeystore();
        KeyStoreUtil.generateMLDSAKey(keyStore, "mldsa", category, false, PASSWORD);

        assertRecoverableEntry(keyStore, "mldsa");
    }

    @Test
    void generateMldsaPreHashKeyIsRecoverableToo() throws Exception {
        KeyStore keyStore = newKeystore();
        KeyStoreUtil.generateMLDSAKey(keyStore, "mldsa-prehash", MLDSASecurityCategory.MLDSA_65, true, PASSWORD);

        assertRecoverableEntry(keyStore, "mldsa-prehash");
    }

    @Test
    void mldsaPublicKeyCanBeRecoveredFromThePrivateKey() {
        KeyStore keyStore = newKeystore();
        KeyStoreUtil.generateMLDSAKey(keyStore, "mldsa", MLDSASecurityCategory.MLDSA_44, false, PASSWORD);

        SpkiKeyValue spki = KeyStoreUtil.spkiKeyValueFromPrivateKey(keyStore, "mldsa", PASSWORD);
        assertNotNull(spki.getValue());
        assertTrue(Base64.getDecoder().decode(spki.getValue()).length > 0);
    }

    @Test
    void entryPasswordIsNotTheSecurityBoundary() {
        KeyStore keyStore = newKeystore();
        KeyStoreUtil.generateMLDSAKey(keyStore, "mldsa", MLDSASecurityCategory.MLDSA_44, false, PASSWORD);

        // BouncyCastle's PKCS12 decrypts key bags when the store is loaded and ignores the
        // password passed to getKey afterwards, so a wrong entry password still returns the
        // key. What actually protects the material is the store password checked by
        // loadKeystore, asserted in loadingWithTheWrongPasswordIsRejected. Recorded here so
        // no caller assumes the per-entry password guards anything.
        SpkiKeyValue spki = KeyStoreUtil.spkiKeyValueFromPrivateKey(keyStore, "mldsa", "wrong-password");
        assertNotNull(spki.getValue());
        assertEquals(KeyStoreUtil.spkiKeyValueFromPrivateKey(keyStore, "mldsa", PASSWORD).getValue(), spki.getValue());
    }

    @ParameterizedTest
    @EnumSource(SLHDSASecurityCategory.class)
    void generateSlhDsaKeyStoresRecoverableEntry(SLHDSASecurityCategory category) throws Exception {
        KeyStore keyStore = newKeystore();
        KeyStoreUtil
                .generateSlhDsaKey(keyStore, "slhdsa", SLHDSAHash.SHA2, category, SLHDSASignatureMode.FAST, false,
                        PASSWORD);

        assertRecoverableEntry(keyStore, "slhdsa");
    }

    @Test
    void generateSlhDsaKeyAcceptsShakeAndSmallSignatures() throws Exception {
        KeyStore keyStore = newKeystore();
        KeyStoreUtil
                .generateSlhDsaKey(keyStore, "slhdsa-shake", SLHDSAHash.SHAKE256, SLHDSASecurityCategory.CATEGORY_1,
                        SLHDSASignatureMode.SMALL, true, PASSWORD);

        assertRecoverableEntry(keyStore, "slhdsa-shake");
    }

    @Test
    void severalAlgorithmsCoexistInOneKeystore() throws Exception {
        KeyStore keyStore = newKeystore();
        KeyStoreUtil.generateRsaKey(keyStore, "rsa", 2048, PASSWORD);
        KeyStoreUtil.generateMLDSAKey(keyStore, "mldsa", MLDSASecurityCategory.MLDSA_44, false, PASSWORD);
        KeyStoreUtil
                .generateSlhDsaKey(keyStore, "slhdsa", SLHDSAHash.SHA2, SLHDSASecurityCategory.CATEGORY_1,
                        SLHDSASignatureMode.FAST, false, PASSWORD);

        assertEquals(3, keyStore.size());
        assertRecoverableEntry(keyStore, "rsa");
        assertRecoverableEntry(keyStore, "mldsa");
        assertRecoverableEntry(keyStore, "slhdsa");

        // The keystore survives a save and load cycle with every algorithm inside it.
        KeyStore reloaded = KeyStoreUtil.loadKeystore(KeyStoreUtil.saveKeystore(keyStore, PASSWORD), PASSWORD);
        assertEquals(3, reloaded.size());
        assertRecoverableEntry(reloaded, "mldsa");
    }

    @Test
    void unknownKeystoreTypeIsRejected() {
        assertThrows(IllegalStateException.class,
                () -> KeyStoreUtil.createNewKeystore("NOT-A-KEYSTORE-TYPE", PASSWORD));
    }

    @Test
    void loadingWithTheWrongPasswordIsRejected() {
        byte[] data = KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD);
        assertThrows(IllegalStateException.class, () -> KeyStoreUtil.loadKeystore(data, "wrong-password"));
    }

    @Test
    void loadingSomethingThatIsNotAKeystoreIsRejected() {
        byte[] notAKeystore = "this is not a PKCS12 keystore".getBytes();
        assertThrows(IllegalStateException.class, () -> KeyStoreUtil.loadKeystore(notAKeystore, PASSWORD));
    }
}
