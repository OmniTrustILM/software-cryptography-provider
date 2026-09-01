package com.otilm.cp.soft.util;

/**
 * Encoding of a stored secret. The version is the first field of the encoded value, so a
 * stored secret always says how to read itself.
 *
 * <p>{@link #V1} is the original scheme and is read-only: it is still decrypted so values
 * written before the upgrade remain readable, but nothing writes it any more.</p>
 */
public enum SecretEncodingVersion {

    /** {@code v1|ciphertext|salt|iterations} — PBE with AES-CBC. Read only. */
    V1("v1"),

    /** {@code v2|ciphertext|salt|iv|iterations} — PBKDF2 with AES-GCM. */
    V2("v2");

    private final String version;

    SecretEncodingVersion(String version) {
        this.version = version;
    }

    public String getVersion() {
        return version;
    }

    /**
     * Resolves the version an encoded secret declares.
     *
     * @throws IllegalArgumentException if the value does not declare a known version
     */
    public static SecretEncodingVersion of(String encodedSecret) {
        if (encodedSecret != null) {
            int separator = encodedSecret.indexOf('|');
            if (separator > 0) {
                String prefix = encodedSecret.substring(0, separator);
                for (SecretEncodingVersion candidate : values()) {
                    if (candidate.version.equals(prefix)) {
                        return candidate;
                    }
                }
            }
        }
        throw new IllegalArgumentException("Secret string is not in the correct format");
    }
}
