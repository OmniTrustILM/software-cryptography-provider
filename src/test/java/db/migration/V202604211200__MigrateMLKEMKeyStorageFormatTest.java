package db.migration;

import com.otilm.cp.soft.util.KeyStoreUtil;
import com.otilm.cp.soft.util.X509Util;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the ML-KEM keystore-format migration logic.
 *
 * <p>These tests work directly with {@link KeyStore} / {@link KeyStoreUtil} and do not require a
 * Spring context or a database. They verify:
 * <ol>
 *   <li>That a keystore carrying an old-format ML-KEM entry (bare PKCS8 key bag, no certificate)
 *       is correctly identified and migrated to the new format (PrivateKeyEntry + orphan cert).</li>
 *   <li>That a keystore that already uses the new format is left untouched.</li>
 *   <li>That the migration does not touch non-ML-KEM entries stored without a certificate.</li>
 * </ol>
 */
class V202604211200__MigrateMLKEMKeyStorageFormatTest {

    private static final String PASSWORD = "test-password";
    private static final String ALIAS = "mlkem-key";

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Generates an ML-KEM-768 key pair using BouncyCastle.
     */
    private static KeyPair generateMlkemKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(MLKEMParameterSpec.fromName("ML-KEM-768"));
        return kpg.generateKeyPair();
    }

    /**
     * Creates a PKCS12 keystore that stores an ML-KEM private key in the <em>old</em> (1.3.1)
     * format: a bare PKCS8ShroudedKeyBag with no certificate chain.
     *
     * <p>BouncyCastle 1.73+ no longer supports {@code setKeyEntry(alias, byte[], null)} on a PKCS12
     * keystore; we use the low-level {@link PKCS12PfxPduBuilder} to construct the binary directly
     * and then load it back through BC's standard {@link KeyStoreUtil#loadKeystore}.
     */
    private static byte[] buildLegacyKeystore(KeyPair mlkemPair) throws Exception {
        return buildBareKeyPkcs12(ALIAS, mlkemPair.getPrivate(), PASSWORD.toCharArray());
    }

    /**
     * Creates a PKCS12 keystore that stores an ML-KEM private key in the <em>new</em> (1.4.0)
     * format: {@code setKeyEntry(alias, PrivateKey, password, chain)}.
     */
    private static byte[] buildNewFormatKeystore(KeyPair mlkemPair) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        ks.load(null, PASSWORD.toCharArray());
        X509Certificate cert = X509Util.generateMLKEMOrphanX509Certificate(mlkemPair);
        ks.setKeyEntry(ALIAS, mlkemPair.getPrivate(), PASSWORD.toCharArray(), new Certificate[]{cert});
        return KeyStoreUtil.saveKeystore(ks, PASSWORD);
    }

    /**
     * Builds a PKCS12 containing a single encrypted key bag for the given private key with no
     * associated certificate bag — i.e. the legacy 1.3.1 storage format.
     */
    private static byte[] buildBareKeyPkcs12(String alias, PrivateKey privateKey, char[] password)
            throws Exception {
        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
        OutputEncryptor keyEncryptor = new JcePKCSPBEOutputEncryptorBuilder(
                PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(password);

        byte[] localKeyId = new byte[20];
        new SecureRandom().nextBytes(localKeyId);

        PKCS12SafeBagBuilder keyBagBuilder = new PKCS12SafeBagBuilder(pkInfo, keyEncryptor);
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, new DEROctetString(localKeyId));

        PKCS12PfxPduBuilder pfxBuilder = new PKCS12PfxPduBuilder();
        pfxBuilder.addData(keyBagBuilder.build());

        PKCS12PfxPdu pfx = pfxBuilder.build(
                new JcePKCS12MacCalculatorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME),
                password);

        return pfx.getEncoded("DER");
    }

    /**
     * Builds a PKCS12 containing:
     * <ul>
     *   <li>A bare (cert-less) key bag for {@code legacyAlias/legacyKey} — legacy format.</li>
     *   <li>A key bag and certificate bag linked by {@code LocalKeyId} for
     *       {@code newAlias/newKey/newCert} — new format.</li>
     * </ul>
     */
    private static byte[] buildMixedPkcs12(String legacyAlias, PrivateKey legacyKey, String newAlias, PrivateKey newKey,
                                           X509Certificate newCert) throws Exception {
        char[] password = PASSWORD.toCharArray();

        OutputEncryptor keyEncryptor = new JcePKCSPBEOutputEncryptorBuilder(
                PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(password);
        OutputEncryptor certEncryptor = new JcePKCSPBEOutputEncryptorBuilder(
                PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(password);

        // Legacy key bag (no cert)
        byte[] legacyLocalKeyId = new byte[20];
        new SecureRandom().nextBytes(legacyLocalKeyId);
        PrivateKeyInfo legacyPkInfo = PrivateKeyInfo.getInstance(legacyKey.getEncoded());
        PKCS12SafeBagBuilder legacyKeyBag = new PKCS12SafeBagBuilder(legacyPkInfo, keyEncryptor);
        legacyKeyBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(legacyAlias));
        legacyKeyBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, new DEROctetString(legacyLocalKeyId));

        // New-format key + cert linked by a shared localKeyId
        byte[] newLocalKeyId = new byte[20];
        new SecureRandom().nextBytes(newLocalKeyId);
        PrivateKeyInfo newPkInfo = PrivateKeyInfo.getInstance(newKey.getEncoded());
        PKCS12SafeBagBuilder newKeyBag = new PKCS12SafeBagBuilder(newPkInfo, keyEncryptor);
        newKeyBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(newAlias));
        newKeyBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, new DEROctetString(newLocalKeyId));

        PKCS12SafeBagBuilder newCertBag = new PKCS12SafeBagBuilder(new JcaX509CertificateHolder(newCert));
        newCertBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(newAlias));
        newCertBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, new DEROctetString(newLocalKeyId));

        PKCS12PfxPduBuilder pfxBuilder = new PKCS12PfxPduBuilder();
        pfxBuilder.addData(legacyKeyBag.build());
        pfxBuilder.addData(newKeyBag.build());
        pfxBuilder.addEncryptedData(certEncryptor, newCertBag.build());

        PKCS12PfxPdu pfx = pfxBuilder.build(new JcePKCS12MacCalculatorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME), password);

        return pfx.getEncoded("DER");
    }

    /**
     * Applies the same in-process migration logic used by
     * {@link V202604211200__MigrateMLKEMKeyStorageFormat}: for every alias that has no certificate
     * and whose recovered key has an algorithm starting with {@code "ML-KEM"}, replaces the bare
     * key bag with a proper PrivateKeyEntry + orphan cert.
     *
     * <p>The public key is supplied via the {@code publicKeys} map (simulating the lookup that the
     * real migration performs against the {@code key_data} table).
     *
     * @return {@code true} if at least one entry was migrated.
     */
    private static boolean applyMigrationLogic(KeyStore ks, java.util.Map<String, PublicKey> publicKeys) throws Exception {
        boolean modified = false;
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.getCertificate(alias) != null) {
                continue; // already new format
            }
            Key key = ks.getKey(alias, PASSWORD.toCharArray());
            if (key == null || !key.getAlgorithm().startsWith("ML-KEM")) {
                continue;
            }
            PublicKey publicKey = publicKeys.get(alias);
            assertNotNull(publicKey, "Public key must be provided for alias: " + alias);

            KeyPair kp = new KeyPair(publicKey, (PrivateKey) key);
            X509Certificate orphanCert = X509Util.generateMLKEMOrphanX509Certificate(kp);
            ks.deleteEntry(alias);
            ks.setKeyEntry(alias, (PrivateKey) key, PASSWORD.toCharArray(), new Certificate[]{orphanCert});
            modified = true;
        }
        return modified;
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    void legacyFormatIsDetectedAndMigrated() throws Exception {
        KeyPair mlkemPair = generateMlkemKeyPair();
        byte[] legacyBytes = buildLegacyKeystore(mlkemPair);

        // Verify the legacy keystore really has no certificate for the alias.
        KeyStore legacyKs = KeyStoreUtil.loadKeystore(legacyBytes, PASSWORD);
        assertNull(legacyKs.getCertificate(ALIAS),
                "Legacy keystore must have no certificate for ML-KEM alias");

        // Run migration logic.
        java.util.Map<String, PublicKey> publicKeys = new java.util.HashMap<>();
        publicKeys.put(ALIAS, mlkemPair.getPublic());
        boolean modified = applyMigrationLogic(legacyKs, publicKeys);

        assertTrue(modified, "Migration must report that it modified the keystore");

        // After migration the alias must have a certificate.
        Certificate migratedCert = legacyKs.getCertificate(ALIAS);
        assertNotNull(migratedCert, "Migrated keystore must have a certificate for ML-KEM alias");

        // The certificate's public key must match the original ML-KEM public key.
        assertArrayEquals(
                mlkemPair.getPublic().getEncoded(),
                migratedCert.getPublicKey().getEncoded(),
                "Certificate public key must match the original ML-KEM public key");

        // The private key must still be recoverable after migration.
        Key recoveredKey = legacyKs.getKey(ALIAS, PASSWORD.toCharArray());
        assertNotNull(recoveredKey, "Private key must be recoverable after migration");
        assertTrue(recoveredKey.getAlgorithm().startsWith("ML-KEM"),
                "Recovered key algorithm must start with ML-KEM");
        assertArrayEquals(
                mlkemPair.getPrivate().getEncoded(),
                recoveredKey.getEncoded(),
                "Recovered private key bytes must match original");
    }

    @Test
    void newFormatIsNotModified() throws Exception {
        KeyPair mlkemPair = generateMlkemKeyPair();
        byte[] newFormatBytes = buildNewFormatKeystore(mlkemPair);

        KeyStore newKs = KeyStoreUtil.loadKeystore(newFormatBytes, PASSWORD);
        assertNotNull(newKs.getCertificate(ALIAS),
                "New-format keystore must already have a certificate");

        java.util.Map<String, PublicKey> publicKeys = new java.util.HashMap<>();
        publicKeys.put(ALIAS, mlkemPair.getPublic());
        boolean modified = applyMigrationLogic(newKs, publicKeys);

        assertFalse(modified, "Migration must not modify an already-new-format keystore");
    }

    @Test
    void nonMlkemBareEntryIsIgnored() throws Exception {
        // Store an EC key in bare-bytes format (unusual but should not be touched by this migration).
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        ecKpg.initialize(new java.security.spec.ECGenParameterSpec("P-256"));
        KeyPair ecPair = ecKpg.generateKeyPair();

        // Build a PKCS12 with a bare EC key bag (no cert) using the low-level builder, then load
        // it via the standard path so the KeyStore is in the state the migration would encounter.
        byte[] keystoreBytes = buildBareKeyPkcs12("ec-key", ecPair.getPrivate(), PASSWORD.toCharArray());
        KeyStore ks = KeyStoreUtil.loadKeystore(keystoreBytes, PASSWORD);

        java.util.Map<String, PublicKey> publicKeys = new java.util.HashMap<>();
        boolean modified = applyMigrationLogic(ks, publicKeys);

        assertFalse(modified, "Migration must not touch non-ML-KEM bare key entries");
        assertNull(ks.getCertificate("ec-key"),
                "EC bare entry must remain untouched (no certificate added)");
    }

    @Test
    void mixedKeystoreMigratesOnlyMlkemEntry() throws Exception {
        KeyPair mlkemPair = generateMlkemKeyPair();

        // Generate a regular EC key stored in the new (normal) format alongside the legacy ML-KEM key.
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        ecKpg.initialize(new java.security.spec.ECGenParameterSpec("P-256"));
        KeyPair ecPair = ecKpg.generateKeyPair();
        X509Certificate ecCert = X509Util.generateEcdsaOrphanX509Certificate(ecPair);

        // Build a PKCS12 that holds both a legacy ML-KEM key (bare, no cert) and a normal EC
        // entry (key + cert) using the low-level builder.
        byte[] keystoreBytes = buildMixedPkcs12(ALIAS, mlkemPair.getPrivate(), "ec-key", ecPair.getPrivate(), ecCert);
        KeyStore ks = KeyStoreUtil.loadKeystore(keystoreBytes, PASSWORD);

        java.util.Map<String, PublicKey> publicKeys = new java.util.HashMap<>();
        publicKeys.put(ALIAS, mlkemPair.getPublic());
        boolean modified = applyMigrationLogic(ks, publicKeys);

        assertTrue(modified);
        assertNotNull(ks.getCertificate(ALIAS), "ML-KEM alias must now have a certificate");
        assertNotNull(ks.getCertificate("ec-key"), "EC alias must still have its original certificate");
    }
}
