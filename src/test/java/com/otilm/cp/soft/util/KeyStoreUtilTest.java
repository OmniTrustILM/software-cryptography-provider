package com.otilm.cp.soft.util;

import com.otilm.api.model.connector.cryptography.key.value.SpkiKeyValue;
import com.otilm.cp.soft.collection.EcdsaCurveName;
import com.otilm.cp.soft.collection.FalconDegree;
import com.otilm.cp.soft.collection.MLKEMSecurityCategory;
import com.otilm.cp.soft.exception.CryptographicOperationException;
import com.otilm.cp.soft.model.CachedKeyData;
import com.otilm.cp.soft.model.CachedKeyMaterial;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.KeyStore;
import java.security.Security;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class KeyStoreUtilTest {

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

    // -------------------------------------------------------------------------
    // createNewKeystore / loadKeystore / saveKeystore
    // -------------------------------------------------------------------------

    @Test
    void createNewKeystoreProducesNonEmptyBytes() {
        byte[] bytes = KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD);
        assertNotNull(bytes);
        assertTrue(bytes.length > 0);
    }

    @Test
    void loadKeystoreRoundtrip() throws Exception {
        byte[] bytes = KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD);
        KeyStore ks = KeyStoreUtil.loadKeystore(bytes, PASSWORD);
        assertNotNull(ks);
        assertEquals(0, ks.size());
    }

    @Test
    void saveAndLoadKeystorePreservesEntries() throws Exception {
        byte[] initial = KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD);
        KeyStore ks = KeyStoreUtil.loadKeystore(initial, PASSWORD);
        KeyStoreUtil.generateEcdsaKey(ks, "ec-key", EcdsaCurveName.secp256r1, PASSWORD);

        byte[] saved = KeyStoreUtil.saveKeystore(ks, PASSWORD);
        KeyStore loaded = KeyStoreUtil.loadKeystore(saved, PASSWORD);

        assertTrue(loaded.containsAlias("ec-key"));
        assertNotNull(loaded.getCertificate("ec-key"));
    }

    // -------------------------------------------------------------------------
    // generateMLKEMKey
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @EnumSource(MLKEMSecurityCategory.class)
    void generateMlkemKeyReturnsPublicKeyWithCertificate(MLKEMSecurityCategory category) throws Exception {
        byte[] bytes = KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD);
        KeyStore ks = KeyStoreUtil.loadKeystore(bytes, PASSWORD);

        BCMLKEMPublicKey publicKey = KeyStoreUtil.generateMLKEMKey(ks, "mlkem", category, PASSWORD);

        assertNotNull(publicKey);
        assertTrue(publicKey.getAlgorithm().startsWith("ML-KEM"));
        assertTrue(ks.containsAlias("mlkem"));
        // New 1.4.0 format: every ML-KEM entry must have an orphan certificate.
        assertNotNull(ks.getCertificate("mlkem"),
                "ML-KEM entry must be stored with an orphan certificate in the new format");
        assertArrayEquals(publicKey.getEncoded(), ks.getCertificate("mlkem").getPublicKey().getEncoded(),
                "Certificate must embed the same public key that was generated");
    }

    // -------------------------------------------------------------------------
    // spkiKeyValueFromKeyStore
    // -------------------------------------------------------------------------

    @Test
    void spkiKeyValueFromKeyStoreMatchesGeneratedPublicKey() {
        byte[] bytes = KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD);
        KeyStore ks = KeyStoreUtil.loadKeystore(bytes, PASSWORD);
        BCMLKEMPublicKey publicKey = KeyStoreUtil.generateMLKEMKey(ks, "mlkem", MLKEMSecurityCategory.CATEGORY_3, PASSWORD);

        SpkiKeyValue spki = KeyStoreUtil.spkiKeyValueFromKeyStore(ks, "mlkem");

        assertNotNull(spki);
        assertNotNull(spki.getValue());
        byte[] decodedSpki = Base64.getDecoder().decode(spki.getValue());
        assertArrayEquals(publicKey.getEncoded(), decodedSpki,
                "SPKI value must match the encoded form of the generated public key");
    }

    // -------------------------------------------------------------------------
    // generateEcdsaKey
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @EnumSource(value = EcdsaCurveName.class, names = {"secp256r1", "secp384r1", "secp521r1"})
    void generateEcdsaKeyStoresEntryWithCertificate(EcdsaCurveName curve) throws Exception {
        byte[] bytes = KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD);
        KeyStore ks = KeyStoreUtil.loadKeystore(bytes, PASSWORD);

        KeyStoreUtil.generateEcdsaKey(ks, "ec-key", curve, PASSWORD);

        assertTrue(ks.containsAlias("ec-key"));
        assertNotNull(ks.getCertificate("ec-key"));
        assertNotNull(ks.getKey("ec-key", PASSWORD.toCharArray()));
    }

    // -------------------------------------------------------------------------
    // generateFalconKey
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @EnumSource(FalconDegree.class)
    void generateFalconKeyStoresEntryWithCertificate(FalconDegree degree) throws Exception {
        byte[] bytes = KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD);
        KeyStore ks = KeyStoreUtil.loadKeystore(bytes, PASSWORD);

        KeyStoreUtil.generateFalconKey(ks, "falcon-key", degree, PASSWORD);

        assertTrue(ks.containsAlias("falcon-key"));
        assertNotNull(ks.getCertificate("falcon-key"));
    }

    // -------------------------------------------------------------------------
    // deleteAliasFromKeyStore
    // -------------------------------------------------------------------------

    @Test
    void deleteAliasRemovesEntry() throws Exception {
        byte[] bytes = KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD);
        KeyStore ks = KeyStoreUtil.loadKeystore(bytes, PASSWORD);
        KeyStoreUtil.generateEcdsaKey(ks, "ec-key", EcdsaCurveName.secp256r1, PASSWORD);
        assertTrue(ks.containsAlias("ec-key"));

        KeyStoreUtil.deleteAliasFromKeyStore(ks, "ec-key");

        assertFalse(ks.containsAlias("ec-key"));
    }

    @Test
    void deleteNonExistentAliasDoesNotThrow() {
        byte[] bytes = KeyStoreUtil.createNewKeystore("PKCS12", PASSWORD);
        KeyStore ks = KeyStoreUtil.loadKeystore(bytes, PASSWORD);

        assertDoesNotThrow(() -> KeyStoreUtil.deleteAliasFromKeyStore(ks, "non-existent"));
    }

    // -------------------------------------------------------------------------
    // getPrivateKey / getPublicKey — error paths
    // -------------------------------------------------------------------------

    @Test
    void getPrivateKey_missingAlias_throwsCryptographicOperationException() {
        CachedKeyData key = new CachedKeyData(UUID.randomUUID(), UUID.randomUUID(), "ghost-alias",
                null, null, null, null, null, 0, List.of());
        CachedKeyMaterial material = new CachedKeyMaterial(Map.of(), Map.of());

        assertThrows(CryptographicOperationException.class,
                () -> KeyStoreUtil.getPrivateKey(key, material));
    }

    @Test
    void getPublicKey_missingAlias_throwsCryptographicOperationException() {
        CachedKeyData key = new CachedKeyData(UUID.randomUUID(), UUID.randomUUID(), "ghost-alias",
                null, null, null, null, null, 0, List.of());
        CachedKeyMaterial material = new CachedKeyMaterial(Map.of(), Map.of());

        assertThrows(CryptographicOperationException.class,
                () -> KeyStoreUtil.getPublicKey(key, material));
    }
}
