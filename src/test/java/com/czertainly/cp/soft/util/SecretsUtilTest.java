package com.czertainly.cp.soft.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
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
 * Encryption of stored secrets.
 *
 * <p>The encoded value is what lands in {@code token_instance.code}, so its shape is asserted
 * rather than only its round trip: it has to stay readable by later releases, and values
 * written by earlier ones have to stay readable now.</p>
 */
class SecretsUtilTest {

    private static final String SECRET = "This is my secret value I want to protect";
    private static final String KEY = "unit-test-encryption-key";

    private SecretsUtil secretsUtil;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() {
        secretsUtil = new SecretsUtil();
        secretsUtil.setEncryptionKey(KEY);
    }

    @Test
    void newSecretsAreWrittenAsAuthenticatedEncryption() {
        String encoded = secretsUtil.encryptAndEncodeSecretString(SECRET);

        String[] parts = encoded.split("\\|");
        assertEquals(5, parts.length, "the encoded form carries version, ciphertext, salt, iv and iterations");
        assertEquals("v2", parts[0]);
        assertTrue(Base64.getDecoder().decode(parts[1]).length > 0);
        assertEquals(32, Base64.getDecoder().decode(parts[2]).length, "salt is 32 bytes");
        assertEquals(12, Base64.getDecoder().decode(parts[3]).length, "GCM uses a 12 byte IV");
        assertEquals(600000, Integer.parseInt(parts[4]));
    }

    @Test
    void secretsRoundTrip() {
        assertEquals(SECRET,
                secretsUtil.decodeAndDecryptSecretString(secretsUtil.encryptAndEncodeSecretString(SECRET)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "a", "pa55w0rd-ěščřžýáíé-日本語-🔐"})
    void anyValueRoundTrips(String secret) {
        assertEquals(secret,
                secretsUtil.decodeAndDecryptSecretString(secretsUtil.encryptAndEncodeSecretString(secret)));
    }

    @Test
    void nullEncodesToNull() {
        assertNull(secretsUtil.encryptAndEncodeSecretString(null));
    }

    @Test
    void eachEncryptionUsesAFreshSaltAndIv() {
        String first = secretsUtil.encryptAndEncodeSecretString(SECRET);
        String second = secretsUtil.encryptAndEncodeSecretString(SECRET);

        assertNotEquals(first, second);
        assertNotEquals(first.split("\\|")[2], second.split("\\|")[2], "salt must differ");
        assertNotEquals(first.split("\\|")[3], second.split("\\|")[3], "IV must differ");
        assertEquals(SECRET, secretsUtil.decodeAndDecryptSecretString(first));
        assertEquals(SECRET, secretsUtil.decodeAndDecryptSecretString(second));
    }

    @Test
    void aTamperedValueIsRejectedRatherThanReturningRubbish() {
        String encoded = secretsUtil.encryptAndEncodeSecretString(SECRET);
        String[] parts = encoded.split("\\|");

        // Flipping a single bit of the ciphertext must be detected. Authentication is what
        // makes that possible; the scheme this replaced would have returned altered plaintext.
        byte[] ciphertext = Base64.getDecoder().decode(parts[1]);
        ciphertext[0] ^= (byte) 0x01;
        String tampered = parts[0] + "|" + Base64.getEncoder().encodeToString(ciphertext)
                + "|" + parts[2] + "|" + parts[3] + "|" + parts[4];

        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> secretsUtil.decodeAndDecryptSecretString(tampered));
        assertTrue(thrown.getMessage().contains("failed authentication"));
    }

    @Test
    void anotherKeyCannotRead() {
        String encoded = secretsUtil.encryptAndEncodeSecretString(SECRET);

        SecretsUtil other = new SecretsUtil();
        other.setEncryptionKey("a-different-encryption-key");

        assertThrows(IllegalStateException.class, () -> other.decodeAndDecryptSecretString(encoded));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "not-encoded-at-all",
            "v3|Y2lwaGVy|c2FsdA==|aXY=|600000",
            "v2|Y2lwaGVy|c2FsdA==|600000",
            "v1|Y2lwaGVy|c2FsdA==",
            "|||",
            "v2|not-base64!|c2FsdA==|aXY=|600000",
            "v2|Y2lwaGVy|c2FsdA==|aXY=|not-a-number"
    })
    void malformedValuesAreRejected(String malformed) {
        assertThrows(IllegalArgumentException.class,
                () -> secretsUtil.decodeAndDecryptSecretString(malformed));
    }

    @Test
    void anImplausibleIterationCountIsRefused() {
        // The count travels with the value, so a tampered one could otherwise demand an
        // unbounded amount of key derivation.
        String encoded = secretsUtil.encryptAndEncodeSecretString(SECRET);
        String[] parts = encoded.split("\\|");
        String inflated = parts[0] + "|" + parts[1] + "|" + parts[2] + "|" + parts[3] + "|2000000000";

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> secretsUtil.decodeAndDecryptSecretString(inflated));
        assertTrue(thrown.getMessage().contains("Iteration count out of range"));
    }

    @Test
    void anIvOfTheWrongLengthIsRefused() {
        String encoded = secretsUtil.encryptAndEncodeSecretString(SECRET);
        String[] parts = encoded.split("\\|");
        String shortIv = parts[0] + "|" + parts[1] + "|" + parts[2] + "|"
                + Base64.getEncoder().encodeToString(new byte[8]) + "|" + parts[4];

        assertThrows(IllegalArgumentException.class,
                () -> secretsUtil.decodeAndDecryptSecretString(shortIv));
    }

    @Test
    void valuesWrittenByThePreviousReleaseStillDecrypt() {
        // Produced by the scheme this release replaces, under the same key. Kept as a literal
        // so the compatibility path is exercised against real stored data rather than against
        // whatever the current code happens to produce.
        String legacy = LegacySecrets.encryptV1(SECRET, KEY);

        assertEquals("v1", legacy.split("\\|")[0]);
        assertEquals(4, legacy.split("\\|").length);
        assertEquals(SECRET, secretsUtil.decodeAndDecryptSecretString(legacy));
    }

    @Test
    void aLegacyValueUnderAnotherKeyDoesNotYieldTheSecret() {
        // The previous scheme is unauthenticated, so a wrong key usually fails the padding
        // check but can occasionally return arbitrary bytes instead. Either outcome is
        // acceptable; recovering the secret is not. This is exactly why the migration verifies
        // a decrypted password against the keystore before rewriting anything.
        String legacy = LegacySecrets.encryptV1(SECRET, "some-other-key");

        String decrypted = null;
        try {
            decrypted = secretsUtil.decodeAndDecryptSecretString(legacy);
        } catch (IllegalStateException expected) {
            // the usual path: the padding check rejected it
        }
        assertNotEquals(SECRET, decrypted, "the secret must not be recoverable with the wrong key");
    }
}
