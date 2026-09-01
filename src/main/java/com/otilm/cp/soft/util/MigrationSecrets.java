package com.otilm.cp.soft.util;

/**
 * Builds a {@link SecretsUtil} for the Flyway Java migrations.
 *
 * <p>
 * Migrations run before and outside the application context, so they cannot have one injected. They read the key from
 * the environment exactly as the application does, falling back to the same published default when
 * {@code ENCRYPTION_KEY} is unset, so a migration decrypts what the running connector wrote.
 * </p>
 */
public final class MigrationSecrets {

    private MigrationSecrets() {
    }

    /** The fallback used when {@code ENCRYPTION_KEY} is unset. */
    public static String publishedDefaultKey() {
        return SecretsUtil.PUBLISHED_DEFAULT_KEY;
    }

    public static SecretsUtil forMigration() {
        String key = System.getenv("ENCRYPTION_KEY");
        SecretsUtil secretsUtil = new SecretsUtil();
        secretsUtil.setEncryptionKey(key == null ? SecretsUtil.PUBLISHED_DEFAULT_KEY : key);
        return secretsUtil;
    }
}
