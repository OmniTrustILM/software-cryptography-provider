package com.otilm.cp.soft.util;

/**
 * Hands the configured {@link SecretsUtil} to code that Spring cannot inject into.
 *
 * <p>Only {@code TokenInstance} needs this: a JPA entity is not a managed bean. Doing the
 * work in an {@code AttributeConverter} instead would make Spring inject it properly, but a
 * converter runs on every hydration, so listing tokens would derive a key per row on a path
 * that never looks at the password. Decrypting inside the accessor keeps that cost where the
 * password is actually used.</p>
 *
 * <p>Everything else takes {@link SecretsUtil} by injection. Tests construct their own
 * instance rather than reaching through here.</p>
 */
public final class SecretsUtilHolder {

    private static SecretsUtil instance;

    private SecretsUtilHolder() {
    }

    /**
     * Publishes the instance the entity accessors use. Called once by Spring, and by tests
     * that exercise the entity without a context. A test that calls this must put the previous
     * value back, which {@link #current()} provides.
     */
    public static void configure(SecretsUtil secretsUtil) {
        instance = secretsUtil;
    }

    /** The instance in use, or {@code null} if none has been published yet. */
    public static SecretsUtil current() {
        return instance;
    }

    private static SecretsUtil get() {
        if (instance == null) {
            throw new IllegalStateException("SecretsUtil has not been configured yet");
        }
        return instance;
    }

    public static String encrypt(String secret) {
        return get().encryptAndEncodeSecretString(secret);
    }

    public static String decrypt(String encoded) {
        return get().decodeAndDecryptSecretString(encoded);
    }
}
