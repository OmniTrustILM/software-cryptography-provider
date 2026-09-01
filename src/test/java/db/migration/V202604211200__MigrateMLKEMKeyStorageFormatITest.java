package db.migration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.cp.soft.Application;
import com.otilm.cp.soft.util.KeyStoreUtil;
import com.otilm.cp.soft.util.MigrationSecrets;
import com.otilm.cp.soft.util.X509Util;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DEROctetString;
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
import org.flywaydb.core.api.configuration.Configuration;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Spring Boot integration test for {@link V202604211200__MigrateMLKEMKeyStorageFormat}.
 *
 * <p>
 * The test seeds the in-memory HSQL database with a {@code token_instance} row that contains a legacy ML-KEM keystore
 * (private key stored as raw PKCS8 bytes, no certificate chain) and a corresponding {@code key_data} row that holds the
 * public key in SPKI format — exactly the state that would be present after upgrading from 1.3.1 to 1.4.0 without
 * running any migration.
 *
 * <p>
 * After running the migration, it asserts that:
 * <ul>
 * <li>The keystore blob in {@code token_instance.data} now contains an orphan certificate for every ML-KEM alias.</li>
 * <li>The private key is still recoverable and its bytes are unchanged.</li>
 * <li>Non-ML-KEM entries in the same keystore are untouched.</li>
 * <li>Token instances that already use the new format are not re-written.</li>
 * </ul>
 */
@SpringBootTest(classes = Application.class)
class V202604211200__MigrateMLKEMKeyStorageFormatITest {

    private static final String PASSWORD = "integration-test-password";
    private static final String MLKEM_ALIAS = "my-mlkem-key";
    private static final String ECDSA_ALIAS = "my-ecdsa-key";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private DataSource dataSource;

    /**
     * UUIDs of rows created during a test — cleaned up in @AfterEach.
     */
    private final Set<UUID> createdTokens = new HashSet<>();

    @BeforeAll
    static void ensureBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @AfterEach
    void cleanUp() throws Exception {
        if (createdTokens.isEmpty()) {
            return;
        }
        try (Connection conn = dataSource.getConnection();
                PreparedStatement deleteKeys = conn
                        .prepareStatement("DELETE FROM key_data WHERE token_instance_uuid = ?");
                PreparedStatement deleteToken = conn.prepareStatement("DELETE FROM token_instance WHERE uuid = ?")) {
            conn.setAutoCommit(true);
            for (UUID tokenUuid : createdTokens) {
                deleteKeys.setObject(1, tokenUuid);
                deleteKeys.executeUpdate();
                deleteToken.setObject(1, tokenUuid);
                deleteToken.executeUpdate();
            }
        }
        createdTokens.clear();
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    void migrationConvertsLegacyMlkemEntry() throws Exception {
        KeyPair mlkemPair = generateMlkemKeyPair();

        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);

            // Seed the database with a legacy token instance.
            UUID tokenUuid = UUID.randomUUID();
            byte[] legacyKeystore = buildLegacyKeystore(mlkemPair, PASSWORD);
            String encryptedPassword = MigrationSecrets.forMigration().encryptAndEncodeSecretString(PASSWORD);
            insertTokenInstance(conn, tokenUuid, encryptedPassword, legacyKeystore);

            // Seed the key_data row (public key in SPKI format, as written by KeyManagementServiceImpl).
            UUID keyDataUuid = UUID.randomUUID();
            insertMlkemPublicKeyData(conn, keyDataUuid, tokenUuid, MLKEM_ALIAS, mlkemPair.getPublic());
            createdTokens.add(tokenUuid);

            // Run the migration.
            V202604211200__MigrateMLKEMKeyStorageFormat migration = new V202604211200__MigrateMLKEMKeyStorageFormat();
            migration.migrate(new JdbcMigrationContext(conn));

            // Load the updated keystore from the database.
            KeyStore migratedKs = loadUpdatedKeystore(conn, tokenUuid, PASSWORD);

            // The ML-KEM alias must now have a certificate.
            Certificate cert = migratedKs.getCertificate(MLKEM_ALIAS);
            assertNotNull(cert, "ML-KEM alias must have an orphan certificate after migration");

            // The certificate's public key must match the original.
            assertArrayEquals(mlkemPair.getPublic().getEncoded(), cert.getPublicKey().getEncoded(),
                    "Certificate public key must match the original ML-KEM public key");

            // The private key must still be recoverable.
            Key recoveredKey = migratedKs.getKey(MLKEM_ALIAS, PASSWORD.toCharArray());
            assertNotNull(recoveredKey, "Private key must still be recoverable after migration");
            assertArrayEquals(mlkemPair.getPrivate().getEncoded(), recoveredKey.getEncoded(),
                    "Private key bytes must be unchanged after migration");
        }
    }

    @Test
    void migrationLeavesNewFormatUnchanged() throws Exception {
        KeyPair mlkemPair = generateMlkemKeyPair();

        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);

            UUID tokenUuid = UUID.randomUUID();
            byte[] newFormatKeystore = buildNewFormatKeystore(mlkemPair, PASSWORD);
            String encryptedPassword = MigrationSecrets.forMigration().encryptAndEncodeSecretString(PASSWORD);
            insertTokenInstance(conn, tokenUuid, encryptedPassword, newFormatKeystore);
            createdTokens.add(tokenUuid);

            // Record the data blob before the migration.
            String dataBefore = queryKeystoreData(conn, tokenUuid);

            V202604211200__MigrateMLKEMKeyStorageFormat migration = new V202604211200__MigrateMLKEMKeyStorageFormat();
            migration.migrate(new JdbcMigrationContext(conn));

            // The data blob must not have changed (migration must not re-write already-new keystores).
            String dataAfter = queryKeystoreData(conn, tokenUuid);
            assertEquals(dataBefore, dataAfter,
                    "A keystore already in the new format must not be rewritten by the migration");
        }
    }

    @Test
    void migrationPreservesNonMlkemEntriesAlongsideMigratedMlkemEntry() throws Exception {
        KeyPair mlkemPair = generateMlkemKeyPair();

        // Build a PKCS12 that holds BOTH a legacy ML-KEM entry AND a normal ECDSA entry using the
        // low-level builder (BC 1.73+ no longer supports setKeyEntry(alias, byte[], null)).
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        ecKpg.initialize(new java.security.spec.ECGenParameterSpec("P-256"));
        KeyPair ecPair = ecKpg.generateKeyPair();
        X509Certificate ecCert = X509Util.generateEcdsaOrphanX509Certificate(ecPair);

        byte[] keystoreBytes = buildMixedPkcs12(MLKEM_ALIAS, mlkemPair.getPrivate(), ECDSA_ALIAS, ecPair.getPrivate(),
                ecCert, PASSWORD.toCharArray());

        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);

            UUID tokenUuid = UUID.randomUUID();
            String encryptedPassword = MigrationSecrets.forMigration().encryptAndEncodeSecretString(PASSWORD);
            insertTokenInstance(conn, tokenUuid, encryptedPassword, keystoreBytes);
            insertMlkemPublicKeyData(conn, UUID.randomUUID(), tokenUuid, MLKEM_ALIAS, mlkemPair.getPublic());
            createdTokens.add(tokenUuid);

            V202604211200__MigrateMLKEMKeyStorageFormat migration = new V202604211200__MigrateMLKEMKeyStorageFormat();
            migration.migrate(new JdbcMigrationContext(conn));

            KeyStore migratedKs = loadUpdatedKeystore(conn, tokenUuid, PASSWORD);

            // ML-KEM must now have a cert.
            assertNotNull(migratedKs.getCertificate(MLKEM_ALIAS), "ML-KEM alias must have a cert after migration");

            // ECDSA entry must still be present and functional.
            assertNotNull(migratedKs.getCertificate(ECDSA_ALIAS), "ECDSA alias must still have its cert");
            Key ecKey = migratedKs.getKey(ECDSA_ALIAS, PASSWORD.toCharArray());
            assertNotNull(ecKey, "ECDSA private key must still be recoverable");
            assertArrayEquals(ecPair.getPrivate().getEncoded(), ecKey.getEncoded(),
                    "ECDSA private key bytes must be unchanged");
        }
    }

    @Test
    void migrationSkipsTokenWithInvalidPasswordFormat() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);

            UUID tokenUuid = UUID.randomUUID();
            // Not a valid V1 encoded secret — migration must skip this token gracefully.
            String invalidCode = "this-is-not-a-valid-encrypted-password";
            byte[] someKeystore = KeyStoreUtil.createNewKeystore("PKCS12", "anypassword");
            insertTokenInstance(conn, tokenUuid, invalidCode, someKeystore);
            createdTokens.add(tokenUuid);

            String dataBefore = queryKeystoreData(conn, tokenUuid);

            V202604211200__MigrateMLKEMKeyStorageFormat migration = new V202604211200__MigrateMLKEMKeyStorageFormat();
            migration.migrate(new JdbcMigrationContext(conn));

            String dataAfter = queryKeystoreData(conn, tokenUuid);
            assertEquals(dataBefore, dataAfter,
                    "Token with undecodable password must be skipped without modifying keystore data");
        }
    }

    @Test
    void migrationSkipsTokenWithCorruptedKeystoreBytes() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);

            UUID tokenUuid = UUID.randomUUID();
            String encryptedPassword = MigrationSecrets.forMigration().encryptAndEncodeSecretString(PASSWORD);
            // Bytes that decode correctly from base64 but are not a PKCS12 keystore.
            byte[] garbage = "not-a-pkcs12-keystore".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            insertTokenInstance(conn, tokenUuid, encryptedPassword, garbage);
            createdTokens.add(tokenUuid);

            String dataBefore = queryKeystoreData(conn, tokenUuid);

            V202604211200__MigrateMLKEMKeyStorageFormat migration = new V202604211200__MigrateMLKEMKeyStorageFormat();
            migration.migrate(new JdbcMigrationContext(conn));

            String dataAfter = queryKeystoreData(conn, tokenUuid);
            assertEquals(dataBefore, dataAfter,
                    "Token with corrupted keystore bytes must be skipped without modifying keystore data");
        }
    }

    @Test
    void migrationSkipsMlkemAliasWhenPublicKeyMissingFromDb() throws Exception {
        KeyPair mlkemPair = generateMlkemKeyPair();
        byte[] legacyKeystore = buildLegacyKeystore(mlkemPair, PASSWORD);

        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);

            UUID tokenUuid = UUID.randomUUID();
            String encryptedPassword = MigrationSecrets.forMigration().encryptAndEncodeSecretString(PASSWORD);
            insertTokenInstance(conn, tokenUuid, encryptedPassword, legacyKeystore);
            // Intentionally no key_data row → public key cannot be reconstructed.
            createdTokens.add(tokenUuid);

            String dataBefore = queryKeystoreData(conn, tokenUuid);

            V202604211200__MigrateMLKEMKeyStorageFormat migration = new V202604211200__MigrateMLKEMKeyStorageFormat();
            migration.migrate(new JdbcMigrationContext(conn));

            String dataAfter = queryKeystoreData(conn, tokenUuid);
            assertEquals(dataBefore, dataAfter,
                    "ML-KEM alias without a corresponding public key in key_data must be skipped");
        }
    }

    @Test
    void migrationSkipsDeactivatedTokenThatHasMlkemKeys() throws Exception {
        KeyPair mlkemPair = generateMlkemKeyPair();

        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);

            UUID tokenUuid = UUID.randomUUID();
            // code = null → deactivated token; migration must detect ML-KEM keys and log a warning but not modify data.
            insertTokenInstance(conn, tokenUuid, null, KeyStoreUtil.createNewKeystore("PKCS12", "any"));
            insertMlkemPublicKeyData(conn, UUID.randomUUID(), tokenUuid, MLKEM_ALIAS, mlkemPair.getPublic());
            createdTokens.add(tokenUuid);

            String dataBefore = queryKeystoreData(conn, tokenUuid);

            V202604211200__MigrateMLKEMKeyStorageFormat migration = new V202604211200__MigrateMLKEMKeyStorageFormat();
            migration.migrate(new JdbcMigrationContext(conn));

            String dataAfter = queryKeystoreData(conn, tokenUuid);
            assertEquals(dataBefore, dataAfter,
                    "Deactivated token (null code) with ML-KEM keys must be skipped without modifying keystore data");
        }
    }

    @Test
    void migrationSkipsDeactivatedTokenWithoutMlkemKeys() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);

            UUID tokenUuid = UUID.randomUUID();
            // code = null → deactivated token with no ML-KEM keys; must be skipped silently.
            insertTokenInstance(conn, tokenUuid, null, KeyStoreUtil.createNewKeystore("PKCS12", "any"));
            createdTokens.add(tokenUuid);

            String dataBefore = queryKeystoreData(conn, tokenUuid);

            V202604211200__MigrateMLKEMKeyStorageFormat migration = new V202604211200__MigrateMLKEMKeyStorageFormat();
            migration.migrate(new JdbcMigrationContext(conn));

            String dataAfter = queryKeystoreData(conn, tokenUuid);
            assertEquals(dataBefore, dataAfter,
                    "Deactivated token (null code) without ML-KEM keys must be skipped without modifying keystore data");
        }
    }

    @Test
    void migrationSkipsMlkemAliasWhenPublicKeyJsonLacksValueField() throws Exception {
        KeyPair mlkemPair = generateMlkemKeyPair();
        byte[] legacyKeystore = buildLegacyKeystore(mlkemPair, PASSWORD);

        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);

            UUID tokenUuid = UUID.randomUUID();
            String encryptedPassword = MigrationSecrets.forMigration().encryptAndEncodeSecretString(PASSWORD);
            insertTokenInstance(conn, tokenUuid, encryptedPassword, legacyKeystore);

            // key_data row is present but the JSON does not contain the expected 'value' field.
            UUID keyDataUuid = UUID.randomUUID();
            String sql = "INSERT INTO key_data "
                    + "(uuid, name, algorithm, type, format, value, length, token_instance_uuid) "
                    + "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setObject(1, keyDataUuid);
                ps.setString(2, MLKEM_ALIAS);
                ps.setString(3, KeyAlgorithm.MLKEM.name());
                ps.setString(4, KeyType.PUBLIC_KEY.name());
                ps.setString(5, KeyFormat.SPKI.name());
                ps.setString(6, "{\"other\":\"no-value-field-here\"}");
                ps.setInt(7, 768);
                ps.setObject(8, tokenUuid);
                ps.executeUpdate();
            }
            createdTokens.add(tokenUuid);

            String dataBefore = queryKeystoreData(conn, tokenUuid);

            V202604211200__MigrateMLKEMKeyStorageFormat migration = new V202604211200__MigrateMLKEMKeyStorageFormat();
            migration.migrate(new JdbcMigrationContext(conn));

            String dataAfter = queryKeystoreData(conn, tokenUuid);
            assertEquals(dataBefore, dataAfter,
                    "ML-KEM alias whose key_data JSON is missing the 'value' field must be skipped");
        }
    }

    // -------------------------------------------------------------------------
    // Helpers — keystore construction
    // -------------------------------------------------------------------------

    private static KeyPair generateMlkemKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(MLKEMParameterSpec.fromName("ML-KEM-768"));
        return kpg.generateKeyPair();
    }

    /**
     * Builds a PKCS12 keystore in the <em>old</em> (1.3.1) format: bare PKCS8ShroudedKeyBag, no cert.
     *
     * <p>
     * BouncyCastle 1.73+ no longer supports {@code setKeyEntry(alias, byte[], null)} on PKCS12; this method uses the
     * low-level {@link PKCS12PfxPduBuilder} instead.
     */
    private static byte[] buildLegacyKeystore(KeyPair mlkemPair, String password) throws Exception {
        return buildBareKeyPkcs12(MLKEM_ALIAS, mlkemPair.getPrivate(), password.toCharArray());
    }

    /**
     * Builds a PKCS12 keystore in the <em>new</em> (1.4.0) format: PrivateKeyEntry + orphan cert.
     */
    private static byte[] buildNewFormatKeystore(KeyPair mlkemPair, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        ks.load(null, password.toCharArray());
        X509Certificate cert = X509Util.generateMLKEMOrphanX509Certificate(mlkemPair);
        ks.setKeyEntry(MLKEM_ALIAS, mlkemPair.getPrivate(), password.toCharArray(), new Certificate[]{cert});
        return KeyStoreUtil.saveKeystore(ks, password);
    }

    /**
     * Builds a PKCS12 containing a single encrypted key bag for the given private key with no associated certificate
     * bag — i.e. the legacy 1.3.1 storage format.
     */
    private static byte[] buildBareKeyPkcs12(String alias, PrivateKey privateKey, char[] password) throws Exception {
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

        PKCS12PfxPdu pfx = pfxBuilder
                .build(new JcePKCS12MacCalculatorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME), password);

        return pfx.getEncoded("DER");
    }

    /**
     * Builds a PKCS12 containing:
     * <ul>
     * <li>A bare (cert-less) key bag for {@code legacyAlias/legacyKey} — legacy format.</li>
     * <li>A key bag and certificate bag linked by {@code LocalKeyId} for {@code newAlias/newKey/newCert} — new
     * format.</li>
     * </ul>
     */
    private static byte[] buildMixedPkcs12(String legacyAlias, PrivateKey legacyKey, String newAlias, PrivateKey newKey,
            X509Certificate newCert, char[] password) throws Exception {
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

        PKCS12PfxPdu pfx = pfxBuilder
                .build(new JcePKCS12MacCalculatorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME), password);

        return pfx.getEncoded("DER");
    }

    // -------------------------------------------------------------------------
    // Helpers — JDBC data setup / query
    // -------------------------------------------------------------------------

    private static void insertTokenInstance(Connection conn, UUID tokenUuid, String encryptedCode, byte[] keystoreBytes)
            throws Exception {
        String data = Base64.getEncoder().encodeToString(keystoreBytes);
        String sql = "INSERT INTO token_instance (uuid, name, code, data, timestamp) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setObject(1, tokenUuid);
            ps.setString(2, "migration-test-token-" + tokenUuid);
            ps.setString(3, encryptedCode);
            ps.setString(4, data);
            ps.executeUpdate();
        }
    }

    private static void insertMlkemPublicKeyData(Connection conn, UUID keyDataUuid, UUID tokenInstanceUuid,
            String alias, PublicKey publicKey) throws Exception {
        String base64Spki = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        Map<String, String> valueMap = new HashMap<>();
        valueMap.put("value", base64Spki);
        String valueJson = MAPPER.writeValueAsString(valueMap);

        String sql = "INSERT INTO key_data "
                + "(uuid, name, algorithm, type, format, value, length, token_instance_uuid) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setObject(1, keyDataUuid);
            ps.setString(2, alias);
            ps.setString(3, KeyAlgorithm.MLKEM.name());
            ps.setString(4, KeyType.PUBLIC_KEY.name());
            ps.setString(5, KeyFormat.SPKI.name());
            ps.setString(6, valueJson);
            ps.setInt(7, 768); // NIST security category level used as a proxy for key length
            ps.setObject(8, tokenInstanceUuid);
            ps.executeUpdate();
        }
    }

    private static String queryKeystoreData(Connection conn, UUID tokenUuid) throws Exception {
        try (PreparedStatement ps = conn.prepareStatement("SELECT data FROM token_instance WHERE uuid = ?")) {
            ps.setObject(1, tokenUuid);
            try (ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next(), "token_instance row must exist");
                return rs.getString("data");
            }
        }
    }

    private static KeyStore loadUpdatedKeystore(Connection conn, UUID tokenUuid, String password) throws Exception {
        String data = queryKeystoreData(conn, tokenUuid);
        byte[] keystoreBytes = Base64.getDecoder().decode(data);
        return KeyStoreUtil.loadKeystore(keystoreBytes, password);
    }

    // -------------------------------------------------------------------------
    // Minimal Flyway Context adapter
    // -------------------------------------------------------------------------

    /**
     * Minimal implementation of {@link Context} that wraps an existing JDBC {@link Connection}. Flyway's
     * {@link org.flywaydb.core.api.migration.BaseJavaMigration#migrate} only uses {@link Context#getConnection()}, so a
     * stub for {@link Context#getConfiguration()} suffices.
     */
    private record JdbcMigrationContext(Connection connection) implements Context {
        @Override
        public Configuration getConfiguration() {
            return null; // not used by this migration
        }

        @Override
        public Connection getConnection() {
            return connection;
        }
    }
}
