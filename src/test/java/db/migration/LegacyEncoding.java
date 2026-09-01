package db.migration;

import com.czertainly.cp.soft.util.MigrationSecrets;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Writes secrets the way the release before this one did, so the migration can be exercised
 * against rows shaped like the ones already in deployed databases.
 */
final class LegacyEncoding {

    private static final String ALGORITHM = "PBEWithSHA256And256BitAES-CBC-BC";
    private static final int ITERATIONS = 1000;

    private LegacyEncoding() {
    }

    /** Encodes under the key this installation is configured with. */
    static String v1(String secret) {
        return v1(secret, effectiveKey());
    }

    static String v1(String secret, String encryptionKey) {
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE,
                    factory.generateSecret(new PBEKeySpec(encryptionKey.toCharArray(), salt, ITERATIONS)));

            return "v1|" + Base64.getEncoder().encodeToString(
                    cipher.doFinal(secret.getBytes(StandardCharsets.UTF_8)))
                    + "|" + Base64.getEncoder().encodeToString(salt)
                    + "|" + ITERATIONS;
        } catch (Exception e) {
            throw new IllegalStateException("Cannot write a value in the previous encoding", e);
        }
    }

    /**
     * The key the migration itself will use, so a value written here is one the migration is
     * expected to be able to read.
     */
    private static String effectiveKey() {
        String fromEnvironment = System.getenv("ENCRYPTION_KEY");
        if (fromEnvironment != null) {
            return fromEnvironment;
        }
        // Mirrors MigrationSecrets, which falls back to the published default.
        return MigrationSecrets.publishedDefaultKey();
    }
}
