package db.migration;

import com.otilm.cp.soft.Application;
import com.otilm.cp.soft.util.KeyStoreUtil;
import com.otilm.cp.soft.util.MigrationSecrets;
import com.otilm.cp.soft.util.SecretsUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.flywaydb.core.api.configuration.Configuration;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.sql.DataSource;
import java.security.Security;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Re-encryption of stored keystore passwords.
 *
 * <p>The passwords are what unlock every token's key material, so the migration is asserted on
 * the property that matters: whatever it writes must still decrypt to the original password.
 * A row it cannot read must be left exactly as it was rather than emptied or corrupted.</p>
 */
@SpringBootTest(classes = Application.class)
class V202609011200__ReencryptSecretsWithAuthenticatedEncryptionITest {

    private static final String PASSWORD = "the-keystore-password";

    @Autowired
    private DataSource dataSource;

    private final List<UUID> created = new ArrayList<>();

    @BeforeAll
    static void ensureBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @AfterEach
    void cleanUp() throws Exception {
        if (created.isEmpty()) {
            return;
        }
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);
            try (PreparedStatement ps =
                         conn.prepareStatement("DELETE FROM token_instance WHERE uuid = ?")) {
                for (UUID uuid : created) {
                    ps.setObject(1, uuid);
                    ps.executeUpdate();
                }
            }
        }
        created.clear();
    }

    @Test
    void aPasswordWrittenByThePreviousReleaseIsRewrittenAndStillDecrypts() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);
            UUID uuid = insertToken(conn, LegacyEncoding.v1(PASSWORD));

            String before = storedCode(conn, uuid);
            assertEquals("v1", before.split("\\|")[0]);

            migrate(conn);

            String after = storedCode(conn, uuid);
            assertEquals("v2", after.split("\\|")[0], "the password must be rewritten");
            assertNotEquals(before, after);
            assertEquals(PASSWORD, secrets().decodeAndDecryptSecretString(after),
                    "the rewritten password must still be the original one");
        }
    }

    @Test
    void aPasswordAlreadyInTheCurrentEncodingIsLeftAlone() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);
            String current = secrets().encryptAndEncodeSecretString(PASSWORD);
            UUID uuid = insertToken(conn, current);

            migrate(conn);

            assertEquals(current, storedCode(conn, uuid), "an already converted row must not be rewritten");
        }
    }

    @Test
    void runningTheMigrationTwiceChangesNothingTheSecondTime() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);
            UUID uuid = insertToken(conn, LegacyEncoding.v1(PASSWORD));

            migrate(conn);
            String afterFirst = storedCode(conn, uuid);

            migrate(conn);

            assertEquals(afterFirst, storedCode(conn, uuid));
            assertEquals(PASSWORD, secrets().decodeAndDecryptSecretString(afterFirst));
        }
    }

    @Test
    void aPasswordThatCannotBeReadIsLeftUntouchedRatherThanLost() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);
            // Written under a key this installation does not hold. Even if the unauthenticated
            // legacy scheme happens to decrypt it to arbitrary bytes rather than failing, the
            // result will not open the keystore, so the row must still be left alone.
            String foreign = LegacyEncoding.v1(PASSWORD, "a-key-this-installation-does-not-have");
            UUID uuid = insertToken(conn, foreign);

            migrate(conn);

            assertEquals(foreign, storedCode(conn, uuid),
                    "an unreadable password must survive the migration unchanged");
        }
    }

    @Test
    void aTokenWithoutAPasswordIsIgnored() throws Exception {
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);
            UUID uuid = insertToken(conn, null);

            migrate(conn);

            assertNull(storedCode(conn, uuid));
        }
    }

    @Test
    void aLongPasswordSurvivesTheWiderColumn() throws Exception {
        // The authenticated encoding adds an IV and a tag, so a password that only just fitted
        // the original column no longer does. This is what the widening is for.
        String longPassword = "p".repeat(180);
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);
            UUID uuid = insertToken(conn, LegacyEncoding.v1(longPassword), longPassword);

            migrate(conn);

            String after = storedCode(conn, uuid);
            assertTrue(after.length() > 255, "the rewritten value exceeds the original column width");
            assertEquals(longPassword, secrets().decodeAndDecryptSecretString(after));
        }
    }

    @Test
    void aDatabaseWithNothingToConvertStillMigrates() throws Exception {
        // No rows in the previous encoding: the migration must complete rather than fail on an
        // empty batch, and must leave the row it does find alone.
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);
            String current = secrets().encryptAndEncodeSecretString(PASSWORD);
            UUID uuid = insertToken(conn, current);

            assertDoesNotThrow(() -> migrate(conn));

            assertEquals(current, storedCode(conn, uuid));
        }
    }

    private SecretsUtil secrets() {
        return MigrationSecrets.forMigration();
    }

    private void migrate(Connection conn) throws Exception {
        new V202609011200__ReencryptSecretsWithAuthenticatedEncryption()
                .migrate(new JdbcMigrationContext(conn));
    }

    private UUID insertToken(Connection conn, String code) throws Exception {
        return insertToken(conn, code, PASSWORD);
    }

    /**
     * @param keystorePassword the password the stored keystore actually opens with; the
     *                         migration verifies the decrypted code against it before rewriting
     */
    private UUID insertToken(Connection conn, String code, String keystorePassword) throws Exception {
        UUID uuid = UUID.randomUUID();
        String sql = "INSERT INTO token_instance (uuid, name, code, data, timestamp) "
                + "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setObject(1, uuid);
            ps.setString(2, "reencrypt-test-" + uuid);
            ps.setString(3, code);
            ps.setString(4, Base64.getEncoder().encodeToString(
                    KeyStoreUtil.createNewKeystore("PKCS12", keystorePassword)));
            ps.executeUpdate();
        }
        created.add(uuid);
        return uuid;
    }

    private String storedCode(Connection conn, UUID uuid) throws Exception {
        try (PreparedStatement ps =
                     conn.prepareStatement("SELECT code FROM token_instance WHERE uuid = ?")) {
            ps.setObject(1, uuid);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString("code") : null;
            }
        }
    }

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
