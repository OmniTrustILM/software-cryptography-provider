package db.migration;

import com.otilm.cp.soft.util.DatabaseMigration;
import com.otilm.cp.soft.util.KeyStoreUtil;
import com.otilm.cp.soft.util.MigrationSecrets;
import com.otilm.cp.soft.util.SecretEncodingVersion;
import com.otilm.cp.soft.util.SecretsUtil;
import java.security.Security;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Types;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Re-encrypts stored keystore passwords with the authenticated scheme.
 *
 * <p>
 * Values written before this release use PBE with AES-CBC, which is unauthenticated and derives its key with far too
 * few iterations. This rewrites every one of them in the current scheme and widens the column, which the longer
 * encoding needs.
 * </p>
 *
 * <p>
 * A row that cannot be decrypted is left alone rather than failing the upgrade. That is safe because decryption reads
 * whichever encoding a value declares, so a row left in the old form keeps working exactly as before; it simply does
 * not gain the stronger protection. Such a row could not have been decrypted by the running connector either, so the
 * migration is not what broke it.
 * </p>
 */
@SuppressWarnings("java:S101")
public class V202609011200__ReencryptSecretsWithAuthenticatedEncryption extends BaseJavaMigration {

    private static final Logger logger = LoggerFactory
            .getLogger(V202609011200__ReencryptSecretsWithAuthenticatedEncryption.class);

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202609011200__ReencryptSecretsWithAuthenticatedEncryption
                .getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        SecretsUtil secretsUtil = MigrationSecrets.forMigration();

        // The authenticated encoding carries an IV and a longer ciphertext, so it no longer
        // fits the original column width.
        try (Statement widen = context.getConnection().createStatement()) {
            widen.execute("ALTER TABLE token_instance ALTER COLUMN code TYPE text");
        }

        int converted = 0;
        int skipped = 0;

        String update = "UPDATE token_instance SET code = ? WHERE uuid = ?;";
        try (Statement select = context.getConnection().createStatement();
                PreparedStatement statement = context.getConnection().prepareStatement(update)) {

            ResultSet tokens = select
                    .executeQuery("SELECT uuid, code, data FROM token_instance WHERE code IS NOT NULL;");

            while (tokens.next()) {
                Object uuid = tokens.getObject("uuid");
                String password = recoverPassword(secretsUtil, uuid, tokens.getString("code"),
                        tokens.getString("data"));

                if (password == null) {
                    skipped++;
                } else {
                    statement.setString(1, secretsUtil.encryptAndEncodeSecretString(password));
                    statement.setObject(2, uuid, Types.OTHER);
                    statement.addBatch();
                    converted++;
                }
            }

            if (converted > 0) {
                // Guarded: executing an empty batch is an error on some drivers, and a
                // database with nothing to convert must still upgrade cleanly.
                statement.executeBatch();
            }
        }

        logger
                .info("Re-encrypted {} keystore password(s) with authenticated encryption, {} left "
                        + "in the previous encoding.", converted, skipped);
    }

    /**
     * The password of a row that should be rewritten, or {@code null} to leave the row alone. A row already in the
     * current encoding also returns {@code null}, since it needs no work.
     */
    private static String recoverPassword(SecretsUtil secretsUtil, Object uuid, String stored, String base64Keystore) {
        if (stored == null || stored.isBlank()) {
            // The query excludes null codes, but a blank one would otherwise reach decryption
            // and be reported as a failure rather than simply having nothing to convert.
            return null;
        }
        if (SecretEncodingVersion.V2.getVersion().equals(versionOf(stored))) {
            return null;
        }

        String password;
        try {
            password = secretsUtil.decodeAndDecryptSecretString(stored);
        } catch (RuntimeException e) {
            logger
                    .error("Keystore password of token instance {} was left in the previous encoding "
                            + "because it could not be decrypted: {}", uuid, e.getMessage());
            return null;
        }

        // The previous scheme is unauthenticated, so decrypting under the wrong key can
        // occasionally return arbitrary bytes instead of failing. Writing those back would
        // replace a password that is still recoverable with one that is not, so the candidate
        // has to open the keystore before anything is overwritten.
        if (!opensKeystore(base64Keystore, password)) {
            logger
                    .error("Keystore password of token instance {} was left in the previous "
                            + "encoding: what it decrypted to does not open the keystore.", uuid);
            return null;
        }
        return password;
    }

    private static boolean opensKeystore(String base64Keystore, String password) {
        if (base64Keystore == null || base64Keystore.isEmpty()) {
            // Nothing to verify against; leave the row alone rather than guess.
            return false;
        }
        try {
            KeyStoreUtil.loadKeystore(Base64.getDecoder().decode(base64Keystore), password);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static String versionOf(String stored) {
        int separator = stored == null ? -1 : stored.indexOf('|');
        return separator > 0 ? stored.substring(0, separator) : null;
    }
}
