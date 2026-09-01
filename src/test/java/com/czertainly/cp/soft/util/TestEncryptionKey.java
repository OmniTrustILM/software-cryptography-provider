package com.czertainly.cp.soft.util;

import java.lang.reflect.Field;

/**
 * Saves and restores the encryption key held statically by {@link SecretsUtil}.
 *
 * <p>The key is a static field populated from configuration, so a test that sets it changes
 * it for every test that runs afterwards in the same JVM. The Flyway migrations set it too,
 * and then decrypt with whatever is in place, so a leftover value from one test makes an
 * unrelated one fail depending on execution order. Any test that needs its own key must set
 * it through {@link #set(String)} and put the previous value back in an {@code @AfterAll}.</p>
 */
public final class TestEncryptionKey {

    private TestEncryptionKey() {
    }

    public static String current() {
        try {
            Field field = SecretsUtil.class.getDeclaredField("encryptionKey");
            field.setAccessible(true);
            return (String) field.get(null);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Cannot read the static encryption key", e);
        }
    }

    public static void set(String key) {
        new SecretsUtil().setEncryptionKeyStatic(key);
    }

    public static void restore(String previous) {
        try {
            Field field = SecretsUtil.class.getDeclaredField("encryptionKey");
            field.setAccessible(true);
            field.set(null, previous);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Cannot restore the static encryption key", e);
        }
    }
}
