package com.otilm.cp.soft.logging;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A log line is forwarded to wherever logs are collected, so what opens a token or is the key itself must not reach it.
 * This connector's own lines never carry either; what does is the message of a failure raised by something that was
 * handed one.
 */
class RedactionTest {

    private static final String SECRET = "00000000-the-code-itself";

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {
            "passphrase=00000000-the-code-itself",
            "passphrase: 00000000-the-code-itself",
            "\"passphrase\":\"00000000-the-code-itself\"",
            "'passphrase': '00000000-the-code-itself'",
            "password=00000000-the-code-itself",
            "tokenCode=00000000-the-code-itself",
            "token_code: 00000000-the-code-itself",
            "activationCode=00000000-the-code-itself",
            "secret=00000000-the-code-itself",
            "access_token=00000000-the-code-itself",
            "clientSecret=00000000-the-code-itself",
            "Cannot open keystore, passphrase=00000000-the-code-itself, alias=key-1"})
    void takesOutWhatWasWrittenUnderTheNameOfASecret(String line) {
        // given
        // when
        String redacted = Redaction.of(line);

        // then
        assertFalse(redacted.contains(SECRET), () -> "the secret survived: " + redacted);
        assertTrue(redacted.contains("[redacted]"), () -> "nothing was taken out of: " + redacted);
    }

    /** A value the caller stated as an object rather than as text is taken whole. */
    @Test
    void takesOutASecretStatedAsAnObject() {
        // given
        String line = "{\"password\":{\"value\":\"00000000-the-code-itself\"}}";

        // when
        // then
        assertFalse(Redaction.of(line).contains(SECRET), Redaction.of(line));
    }

    /** A passphrase may contain a space, so a value runs to the end of the field rather than to the first one. */
    @Test
    void takesOutASecretThatContainsASpace() {
        // given
        String line = "passphrase=first part second part";

        // when
        String redacted = Redaction.of(line);

        // then
        assertFalse(redacted.contains("second part"), redacted);
    }

    /** What the line says about the objects it names is beyond the value and survives it. */
    @Test
    void leavesWhatFollowsTheSecretInPlace() {
        // given
        String line = "Cannot open keystore, passphrase=00000000-the-code-itself, alias=key-1";

        // when
        String redacted = Redaction.of(line);

        // then
        assertFalse(redacted.contains(SECRET), redacted);
        assertTrue(redacted.contains("alias=key-1"), () -> "the alias was taken out too: " + redacted);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {
            "{\"Authorization\":\"Basic 00000000-the-code-itself\"}",
            "authorization: Basic 00000000-the-code-itself",
            "\"privateKey\":\"00000000-the-code-itself\"",
            "encryptedPrivateKeyInfo=00000000-the-code-itself",
            "keystore: 00000000-the-code-itself"})
    void takesOutTheCredentialHoweverItIsStated(String line) {
        // given
        // when
        String redacted = Redaction.of(line);

        // then
        assertFalse(redacted.contains(SECRET), () -> "the secret survived: " + redacted);
    }

    /** A key cut off before its closing marker is still the key, so what is left of the line goes with it. */
    @Test
    void takesOutAKeyThatWasCutOff() {
        // given
        String line = "material: -----BEGIN PRIVATE KEY-----\nMIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkq";

        // when
        String redacted = Redaction.of(line);

        // then
        assertFalse(redacted.contains("MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkq"), redacted);
        assertTrue(redacted.contains("material: "), "what came before it is still said");
    }

    /**
     * A line carrying opening markers and no closing one must not be searched once for every marker it carries: the
     * thread writing the line is the thread serving the request.
     */
    @Test
    void takesOutAKeyWithoutSearchingTheLineOncePerMarker() {
        // given
        String adversarial = "-----BEGIN PRIVATE KEY-----\n".repeat(4000);

        // when
        long started = System.nanoTime();
        String redacted = Redaction.of(adversarial);
        long took = (System.nanoTime() - started) / 1_000_000;

        // then
        assertTrue(took < 200, () -> "took " + took + "ms over " + adversarial.length() + " characters");
        assertTrue(redacted.contains("[redacted private key]"), redacted);
    }

    @Test
    void takesOutAKeyWrittenOutInFull() {
        // given
        String line = """
                failed to read material: -----BEGIN ENCRYPTED PRIVATE KEY-----
                MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI
                -----END ENCRYPTED PRIVATE KEY----- for alias key-1""";

        // when
        String redacted = Redaction.of(line);

        // then
        assertFalse(redacted.contains("MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI"), redacted);
        assertTrue(redacted.contains("[redacted private key]"), redacted);
        assertTrue(redacted.contains("for alias key-1"), "what is not the key is still said");
    }

    @Test
    void takesOutTheCredentialOnAnAuthorizationHeader() {
        // given
        String line = "GET /v1/metrics authorization: Bearer eyJhbGciOiJSUzI1NiJ9.body.signature";

        // when
        String redacted = Redaction.of(line);

        // then
        assertFalse(redacted.contains("eyJhbGciOiJSUzI1NiJ9"), redacted);
    }

    /** What a line says about the objects it names is what makes it worth having. */
    @Test
    void leavesAloneALineThatCarriesNoSecret() {
        // given
        String line = "Migrated ML-KEM key 'key-1' in token 4c8f7c10-d5a6-d0ae-4bbf-6b6e8b0cd8a1 to new format";

        // when
        // then
        assertEquals(line, Redaction.of(line));
    }

    @Test
    void saysNothingAboutALineThatSaysNothing() {
        // given
        // when
        // then
        assertNull(Redaction.of(null));
        assertEquals("", Redaction.of(""));
    }
}
