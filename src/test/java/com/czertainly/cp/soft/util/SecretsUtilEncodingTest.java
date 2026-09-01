package com.czertainly.cp.soft.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The encoded form of a stored secret. The value written to token_instance.code is
 * {@code v1|ciphertext|salt|iterations}, and it must stay readable across releases, so the
 * shape of that string is asserted here rather than only its round trip.
 */
class SecretsUtilEncodingTest {

    private static final String SECRET = "This is my secret value I want to protect";

    private static final String TEST_KEY = "unit-test-encryption-key";

    private static String previousKey;

    @BeforeAll
    static void prepare() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        // Set directly rather than through Spring: the encryption key is a static field
        // populated from configuration, and nothing else here needs a context. The previous
        // value is put back afterwards so tests running later in the same JVM, in particular
        // the migration tests, still decrypt with the key they expect.
        previousKey = TestEncryptionKey.current();
        TestEncryptionKey.set(TEST_KEY);
    }

    @AfterAll
    static void restoreKey() {
        TestEncryptionKey.restore(previousKey);
    }

    @Test
    void encodedSecretHasVersionCiphertextSaltAndIterations() {
        String encoded = SecretsUtil.encryptAndEncodeSecretString(SECRET, SecretEncodingVersion.V1);

        String[] parts = encoded.split("\\|");
        assertEquals(4, parts.length, "the encoded form must keep its four fields");
        assertEquals(SecretEncodingVersion.V1.getVersion(), parts[0]);
        assertTrue(Base64.getDecoder().decode(parts[1]).length > 0, "ciphertext must decode");
        assertEquals(32, Base64.getDecoder().decode(parts[2]).length, "salt must stay 32 bytes");
        assertEquals(1000, Integer.parseInt(parts[3]), "iteration count is recorded in the value");
    }

    @Test
    void eachEncryptionUsesAFreshSalt() {
        String first = SecretsUtil.encryptAndEncodeSecretString(SECRET, SecretEncodingVersion.V1);
        String second = SecretsUtil.encryptAndEncodeSecretString(SECRET, SecretEncodingVersion.V1);

        assertNotEquals(first, second, "encrypting the same secret twice must not produce the same value");
        assertNotEquals(first.split("\\|")[2], second.split("\\|")[2], "the salt must differ per encryption");

        // Both still decrypt, because the salt travels with the value.
        assertEquals(SECRET, SecretsUtil.decodeAndDecryptSecretString(first, SecretEncodingVersion.V1));
        assertEquals(SECRET, SecretsUtil.decodeAndDecryptSecretString(second, SecretEncodingVersion.V1));
    }

    @Test
    void nullSecretEncodesToNull() {
        assertNull(SecretsUtil.encryptAndEncodeSecretString(null, SecretEncodingVersion.V1));
    }

    @Test
    void emptySecretRoundTrips() {
        String encoded = SecretsUtil.encryptAndEncodeSecretString("", SecretEncodingVersion.V1);
        assertEquals("", SecretsUtil.decodeAndDecryptSecretString(encoded, SecretEncodingVersion.V1));
    }

    @Test
    void nonAsciiSecretRoundTrips() {
        String secret = "pa55w0rd-ěščřžýáíé-日本語-🔐";
        String encoded = SecretsUtil.encryptAndEncodeSecretString(secret, SecretEncodingVersion.V1);
        assertEquals(secret, SecretsUtil.decodeAndDecryptSecretString(encoded, SecretEncodingVersion.V1));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "not-encoded-at-all",
            "v1|only|three",
            "v2|Y2lwaGVy|c2FsdA==|1000",
            "|||"
    })
    void malformedValuesAreRejected(String malformed) {
        assertThrows(IllegalArgumentException.class,
                () -> SecretsUtil.decodeAndDecryptSecretString(malformed, SecretEncodingVersion.V1));
    }

    @Test
    void aValueEncryptedUnderAnotherKeyDoesNotDecrypt() {
        String encoded = SecretsUtil.encryptAndEncodeSecretString(SECRET, SecretEncodingVersion.V1);
        try {
            TestEncryptionKey.set("a-different-encryption-key");

            // CBC decryption under the wrong key usually fails the padding check, but the
            // resulting plaintext can occasionally carry valid padding by chance. Either
            // outcome is acceptable; recovering the original secret is not.
            String decrypted = null;
            try {
                decrypted = SecretsUtil.decodeAndDecryptSecretString(encoded, SecretEncodingVersion.V1);
            } catch (IllegalStateException expected) {
                // padding or key check rejected the value, which is the usual path
            }
            assertNotEquals(SECRET, decrypted, "the secret must not be recoverable with the wrong key");
        } finally {
            TestEncryptionKey.set(TEST_KEY);
        }
    }
}
